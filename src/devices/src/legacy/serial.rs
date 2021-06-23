// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::legacy::EventFdTrigger;
use logger::metrics::SerialDeviceMetrics;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;
use vm_superio::serial::Error as SerialError;
use vm_superio::serial::SerialEvents;
use vm_superio::Serial;
use vm_superio::Trigger;

use event_manager::{EventOps, Events, MutEventSubscriber};

use logger::{error, warn, IncMetric};
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

impl<W: Write + Send + 'static> BusDevice
    for SerialWrapper<EventFdTrigger, Arc<SerialDeviceMetrics>, W>
{
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            self.0.events().missed_read_count.inc();
            return;
        }
        data[0] = self.0.read(offset as u8);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            self.0.events().missed_write_count.inc();
            return;
        }
        if let Err(e) = self.0.write(offset as u8, data[0]) {
            if let vm_superio::serial::Error::IOError(ref e2) = e {
                if e2.kind() == io::ErrorKind::WouldBlock {
                    // Sending the interrupt may also fail.
                    if let Err(interrupt_err) = self.0.thr_empty_interrupt() {
                        error!("Failed the raise serial IRQ: {}", interrupt_err);
                        // Counter incremented for irq error.
                    }
                }
            }
            // Counter incremented for any handle_write() error.
            error!("Failed the write to serial: {:?}", e);
            self.0.events().error_count.inc();
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
                    Some(errno) if errno == libc::ENOBUFS => {
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
