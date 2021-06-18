// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::legacy::EventFdTrigger;
use libc::ENOBUFS;
use std::io::Write;
use std::result;
use vm_superio::serial::Error as SerialError;
use vm_superio::serial::NoEvents;
use vm_superio::Trigger;

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use vm_superio::serial::SerialEvents;
use vm_superio::Serial;

use event_manager::{EventOps, Events, MutEventSubscriber};

use logger::{error, warn, IncMetric, METRICS};
use utils::epoll::EventSet;

use crate::bus::BusDevice;

#[derive(Debug)]
pub enum RawIOError {
    Serial(SerialError<io::Error>),
}

pub trait RawIOHandler {
    /// Send raw input to this emulated device.
    fn raw_input(&mut self, _data: &[u8]) -> result::Result<(), RawIOError>;
}

impl<EV: SerialEvents, W: Write> RawIOHandler for Serial<EventFdTrigger, EV, W> {
    // This is not used for anything and is basically just a dummy implementation for `raw_input`.
    fn raw_input(&mut self, data: &[u8]) -> result::Result<(), RawIOError> {
        // Fail fast if the serial is serviced with more data than it can buffer.
        if data.len() > self.fifo_capacity() {
            return Err(RawIOError::Serial(SerialError::FullFifo));
        }

        // Before enqueuing bytes we first check if there is enough free space
        // in the FIFO.
        if self.fifo_capacity() >= data.len() {
            self.enqueue_raw_bytes(data).map_err(RawIOError::Serial)?;
        }
        Ok(())
    }
}

impl<EV: SerialEvents + Send + 'static, W: Write + Send + 'static> BusDevice
    for Serial<EventFdTrigger, EV, W>
{
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            METRICS.uart.missed_read_count.inc();
            return;
        }
        data[0] = self.read(offset as u8);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            METRICS.uart.missed_write_count.inc();
            return;
        }
        if let Err(e) = self.write(offset as u8, data[0]) {
            error!("Failed the write to serial: {:?}", e);
            METRICS.uart.error_count.inc();
        }
    }
}

pub struct SerialWrapper<T: Trigger, EV: SerialEvents, W: Write>(pub Serial<T, EV, W>);

impl<EV: SerialEvents, W: Write> SerialWrapper<EventFdTrigger, EV, W> {
    fn handle_ewouldblock(&self, ops: &mut EventOps) {
        let buffer_ready_fd = self.0.buffer_ready_evt_fd();
        let input_fd = self.0.serial_input_fd();
        if input_fd < 0 || buffer_ready_fd < 0 {
            error!("Serial does not have a configured input source.");
            return;
        }
        match ops.add(Events::new(&input_fd, EventSet::IN)) {
            Err(event_manager::Error::FdAlreadyRegistered) => (),
            Err(e) => {
                error!(
                    "Could not register the serial input to the event manager: {:?}",
                    e
                );
            }
            Ok(()) => {
                // Bytes might had come on the unregistered stdin. Try to consume any.
                self.0.signal_buffer_ready().unwrap_or_else(|err| {
                    error!(
                        "Could not signal that serial device buffer is ready: {:?}",
                        err
                    )
                })
            }
        };
    }

    fn recv_bytes(&mut self) -> io::Result<usize> {
        let avail_cap = self.0.fifo_capacity();
        if avail_cap == 0 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }

        if let Some(input) = self.0.input.as_mut() {
            let mut out = vec![0u8; avail_cap];
            let count = input.read(&mut out)?;
            if count > 0 {
                self.0
                    .raw_input(&out[..count])
                    .map_err(|_| io::Error::from_raw_os_error(libc::ENOBUFS))?;
            }

            return Ok(count);
        }

        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }
}

impl<EV: SerialEvents, W: std::io::Write> MutEventSubscriber
    for SerialWrapper<EventFdTrigger, EV, W>
{
    /// Handle events on the serial input fd.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        #[inline]
        fn unregister_source<T: AsRawFd>(ops: &mut EventOps, source: &T) {
            match ops.remove(Events::new(source, EventSet::IN)) {
                Ok(_) => (),
                Err(_) => error!("Could not unregister source fd: {}", source.as_raw_fd()),
            }
        }

        let input_fd = self.0.serial_input_fd();
        let buffer_ready_fd = self.0.buffer_ready_evt_fd();
        if input_fd < 0 || buffer_ready_fd < 0 {
            error!("Serial does not have a configured input source.");
            return;
        }

        if buffer_ready_fd == event.fd() {
            match self.0.consume_buffer_ready_evt() {
                Ok(_) => (),
                Err(err) => {
                    error!("Detach serial device input source due to error in consuming the buffer ready event: {:?}", err);
                    unregister_source(ops, &input_fd);
                    unregister_source(ops, &buffer_ready_fd);
                    return;
                }
            }
        }

        // We expect to receive: `EventSet::IN`, `EventSet::HANG_UP` or
        // `EventSet::ERROR`. To process all these events we just have to
        // read from the serial input.
        match self.recv_bytes() {
            Ok(count) => {
                // Handle EOF if the event came from the input source.
                if input_fd == event.fd() && count == 0 {
                    unregister_source(ops, &input_fd);
                    unregister_source(ops, &buffer_ready_fd);
                    warn!("Detached the serial input due to peer close/error.");
                }
            }
            Err(e) => {
                match e.raw_os_error() {
                    Some(errno) if errno == ENOBUFS => {
                        unregister_source(ops, &input_fd);
                    }
                    Some(errno) if errno == libc::EWOULDBLOCK => {
                        self.handle_ewouldblock(ops);
                    }
                    Some(errno) if errno == libc::ENOTTY => {
                        error!("The serial device does not have the input source attached.");
                        unregister_source(ops, &input_fd);
                        unregister_source(ops, &buffer_ready_fd);
                    }
                    Some(_) | None => {
                        // Unknown error, detach the serial input source.
                        unregister_source(ops, &input_fd);
                        unregister_source(ops, &buffer_ready_fd);
                        warn!("Detached the serial input due to peer close/error.");
                    }
                }
            }
        }
    }

    /// Initial registration of pollable objects.
    /// If serial input is present, register the serial input FD as readable.
    fn init(&mut self, ops: &mut EventOps) {
        if self.0.input.is_some() {
            if let Some(buf_ready_evt) = self.0.buffer_ready_evt.as_ref() {
                if let Err(e) = ops.add(Events::new(&self.0.serial_input_fd(), EventSet::IN)) {
                    error!("Failed to register serial input fd: {}", e);
                }
                if let Err(e) = ops.add(Events::new(buf_ready_evt, EventSet::IN)) {
                    error!("Failed to register serial buffer ready event: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::Write;
    use std::os::unix::io::RawFd;
    use std::sync::{Arc, Mutex};

    use event_manager::{EventManager, SubscriberOps};

    struct SharedBufferInternal {
        read_buf: Vec<u8>,
        write_buf: Vec<u8>,
        evfd: EventFd,
    }

    #[derive(Clone)]
    struct SharedBuffer {
        internal: Arc<Mutex<SharedBufferInternal>>,
        loopback: bool,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                internal: Arc::new(Mutex::new(SharedBufferInternal {
                    read_buf: Vec::new(),
                    write_buf: Vec::new(),
                    evfd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                })),
                loopback: false,
            }
        }

        fn set_loopback(&mut self, loopback: bool) {
            self.loopback = loopback;
        }
    }
    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.loopback {
                self.internal.lock().unwrap().read_buf.write(buf)
            } else {
                self.internal.lock().unwrap().write_buf.write(buf)
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.loopback {
                self.internal.lock().unwrap().read_buf.flush()
            } else {
                self.internal.lock().unwrap().write_buf.flush()
            }
        }
    }
    impl io::Read for SharedBuffer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self
                .internal
                .lock()
                .unwrap()
                .read_buf
                .as_slice()
                .read(buf)?;
            // Need to clear what is read, to simulate consumed inflight bytes.
            self.internal.lock().unwrap().read_buf.drain(0..count);
            Ok(count)
        }
    }
    impl AsRawFd for SharedBuffer {
        fn as_raw_fd(&self) -> RawFd {
            self.internal.lock().unwrap().evfd.as_raw_fd()
        }
    }
    impl ReadableFd for SharedBuffer {}

    #[derive(Clone)]
    // Dummy struct used for simulating a full buffer.
    struct FullDummyBuffer;

    impl io::Write for FullDummyBuffer {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Resource temporarily unavailable",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Resource temporarily unavailable",
            ))
        }
    }

    static RAW_INPUT_BUF: [u8; 3] = [b'a', b'b', b'c'];

    #[test]
    fn test_serial_output() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out.clone()));

        // Invalid write of multiple chars at once.
        serial.write(u64::from(DATA), &[b'x', b'y']);
        // Valid one char at a time writes.
        RAW_INPUT_BUF
            .iter()
            .for_each(|&c| serial.write(u64::from(DATA), &[c]));
        assert_eq!(
            serial_out.internal.lock().unwrap().write_buf.as_slice(),
            &RAW_INPUT_BUF
        );
    }

    #[test]
    fn test_serial_raw_input() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt.try_clone().unwrap(), Box::new(serial_out));

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_RECV_BIT]);
        serial.raw_input(&RAW_INPUT_BUF).unwrap();

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [0u8, 0u8];
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data, [0u8, 0u8]);

        let mut data = [0u8];
        serial.read(u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });

        // Check if reading from the largest u8 offset returns 0.
        serial.read(0xff, &mut data[..]);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_serial_input() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();

        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
            Some(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
        );

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_RECV_BIT]);

        // Prepare the input buffer.
        {
            let mut guard = serial_in_out.internal.lock().unwrap();
            guard.read_buf.write_all(&RAW_INPUT_BUF).unwrap();
            guard.evfd.write(1).unwrap();
        }

        let mut evmgr = EventManager::new().unwrap();
        let serial_wrap = Arc::new(Mutex::new(serial));
        let _id = evmgr.add_subscriber(serial_wrap.clone());

        // Run the event handler which should drive serial input.
        // There should be one event reported (which should have also handled serial input).
        assert_eq!(evmgr.run_with_timeout(50).unwrap(), 1);

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        let mut serial = serial_wrap.lock().unwrap();
        let mut data = [0u8];
        serial.read(u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });
    }

    #[test]
    fn test_serial_thr() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut serial = Serial::new_sink(intr_evt.try_clone().unwrap());

        // write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks)
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_THR_BIT]);
        serial.write(u64::from(DATA), &[b'a']);

        assert_eq!(intr_evt.read().unwrap(), 2);
        let mut data = [0u8];
        serial.read(u64::from(IER), &mut data[..]);
        assert_eq!(data[0] & IER_FIFO_BITS, IER_THR_BIT);
        serial.read(u64::from(IIR), &mut data[..]);
        assert_ne!(data[0] & IIR_THR_BIT, 0);
    }

    #[test]
    fn test_serial_dlab() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(LCR), &[LCR_DLAB_BIT as u8]);
        serial.write(u64::from(DLAB_LOW), &[0x12_u8]);
        serial.write(u64::from(DLAB_HIGH), &[0x34_u8]);

        let mut data = [0u8];
        serial.read(u64::from(LCR), &mut data[..]);
        assert_eq!(data[0], LCR_DLAB_BIT as u8);
        serial.read(u64::from(DLAB_LOW), &mut data[..]);
        assert_eq!(data[0], 0x12);
        serial.read(u64::from(DLAB_HIGH), &mut data[..]);
        assert_eq!(data[0], 0x34);
    }

    #[test]
    fn test_serial_modem() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(MCR), &[MCR_LOOP_BIT as u8]);
        serial.write(u64::from(DATA), &[b'a']);
        serial.write(u64::from(DATA), &[b'b']);
        serial.write(u64::from(DATA), &[b'c']);

        let mut data = [0u8];
        serial.read(u64::from(MSR), &mut data[..]);
        assert_eq!(data[0], DEFAULT_MODEM_STATUS as u8);
        serial.read(u64::from(MCR), &mut data[..]);
        assert_eq!(data[0], MCR_LOOP_BIT as u8);
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    #[test]
    fn test_serial_scratch() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(SCR), &[0x12_u8]);

        let mut data = [0u8];
        serial.read(u64::from(SCR), &mut data[..]);
        assert_eq!(data[0], 0x12_u8);
    }

    #[test]
    fn test_serial_data_len() {
        const LEN: usize = 1;
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let missed_writes_before = METRICS.uart.missed_write_count.count();
        // Trying to write data of length different than the one that we initialized the device with
        // should increase the `missed_write_count` metric.
        serial.write(u64::from(DATA), &[b'x', b'x']);
        let missed_writes_after = METRICS.uart.missed_write_count.count();
        assert_eq!(missed_writes_before, missed_writes_after - 1);

        let data = [b'x'; LEN];
        serial.write(u64::from(DATA), &data);
        // When we write data that has the length used to initialize the device, the `missed_write_count`
        // metric stays the same.
        assert_eq!(missed_writes_before, missed_writes_after - 1);
    }

    #[test]
    fn test_raw_input_err() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let input = [0u8; FIFO_SIZE + 1];
        serial.raw_input(&input).unwrap_err();
    }

    #[test]
    fn test_serial_in_buffer_limit() {
        let mut serial_in_out = SharedBuffer::new();
        serial_in_out.set_loopback(true);

        let mut serial = Serial::new_in_out(
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
            Some(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
        );

        // Send more than buffer capacity bytes.
        let stdin_bytes = vec![0u8; FIFO_SIZE + 1];
        serial_in_out.write_all(&stdin_bytes).unwrap();
        let mut count = serial.recv_bytes().unwrap();
        // Assert that the buffer is full, without the extra bytes
        // written to the standard input.
        assert_eq!(serial.in_buffer.len(), FIFO_SIZE);
        assert_eq!(count, FIFO_SIZE);
        serial.in_buffer.clear();

        // Send an amount of bytes which does not fill up the buffer.
        let chars_count = 10;
        serial_in_out
            .write_all(&stdin_bytes[..FIFO_SIZE - chars_count - 1])
            .unwrap();
        count = serial.recv_bytes().unwrap();
        assert_eq!(serial.in_buffer.len(), FIFO_SIZE - chars_count);
        assert_eq!(count, FIFO_SIZE - chars_count);

        // Send the rest of the bytes which will fill up the buffer.
        serial_in_out
            .write_all(&stdin_bytes[FIFO_SIZE - chars_count..])
            .unwrap();
        count = serial.recv_bytes().unwrap();
        assert_eq!(serial.in_buffer.len(), FIFO_SIZE);
        assert_eq!(count, chars_count);

        // Send and read more than the buffer size.
        // Assert that the buffer stays at its maximum capacity.
        serial_in_out.write_all(&stdin_bytes).unwrap();
        serial.recv_bytes().unwrap_err();
        assert_eq!(serial.in_buffer.len(), FIFO_SIZE);

        // Process part of the buffer, until its last byte.
        for i in 0..FIFO_SIZE - 1 {
            serial.handle_read(DATA);
            assert_eq!(serial.avail_buffer_capacity(), i + 1);
        }

        // Process the last byte and assert that the stdin was kicked for more bytes.
        serial.handle_read(DATA);
        assert_eq!(serial.buffer_ready_evt.as_ref().unwrap().read().unwrap(), 1);
    }

    #[test]
    #[should_panic]
    fn test_avail_buffer_capacity_panic() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let input = vec![0u8; FIFO_SIZE + 1];
        serial.in_buffer.extend(&input);

        // This should panic since it tries to
        serial.avail_buffer_capacity();
    }

    #[test]
    fn serial_output_full_destination_buffer() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = FullDummyBuffer {};

        let mut serial = Serial::new_out(intr_evt.try_clone().unwrap(), Box::new(serial_out));
        // write 1 to the interrupt event fd, so that read doesn't return an error in
        // case the event fd counter is 0
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_THR_BIT]);
        // this write will fail
        serial.write(u64::from(DATA), &[b'a']);

        // verify the interrupt has been triggered even though write fails
        assert_eq!(intr_evt.read().unwrap(), 2);
    }
}
