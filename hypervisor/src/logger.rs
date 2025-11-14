//! Provides a serial port logger implementation.
//!
//! Logging over a serial port is handy for hypervisor / UEFI style environments
//! where you don't have stdout. This version avoids taking a shared reference to
//! a mutable static, so the Rust 2024 compatibility warning goes away, and uses
//! a mutex to allow mutable serial writes.

use {
    crate::intel::support::{inb, outb},
    alloc::boxed::Box,
    core::{fmt, fmt::Write},
    spin::Mutex,
};

/// UART register offsets
const UART_OFFSET_DATA: u16 = 0x0;
const UART_OFFSET_INTERRUPT_ENABLE: u16 = 0x1;
const UART_OFFSET_FIFO_CONTROL: u16 = 0x2;
const UART_OFFSET_LINE_CONTROL: u16 = 0x3;
const UART_OFFSET_MODEM_CONTROL: u16 = 0x4;
const UART_OFFSET_LINE_STATUS: u16 = 0x5;
const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0x0;

/// Global raw pointer to the logger. Kept as a raw pointer so we don't form
/// `&T` from a `static mut`, which is what triggered the Rust 2024 warning.
static mut SERIAL_LOGGER: *const SerialLogger = core::ptr::null();

/// Initialize the serial logger and install it as the global `log` logger.
///
/// This function is **idempotent**: if the logger has already been initialized
/// (for example, by the UEFI module), calling it again will *not* attempt to
/// register another global logger. Instead, it will simply update the global
/// max log level and return. This allows both the UEFI module and the
/// hypervisor to call `logger::init` safely without "fighting" over ownership
/// of the `log` logger.
pub fn init(port: SerialPort, level: log::LevelFilter) {
    unsafe {
        // If we already have a global logger, assume it was initialized by UEFI
        // (or an earlier phase) and just update the max level. Avoid calling
        // `log::set_logger` again, which would otherwise return an error and
        // panic if we unwrap it.
        if !SERIAL_LOGGER.is_null() {
            log::set_max_level(level);
            return;
        }
    }

    // Allocate and leak, so we have a `'static` logger for `log::set_logger`.
    let logger = SerialLogger::new(port);
    let logger_ref: &'static SerialLogger = Box::leak(Box::new(logger));

    unsafe {
        SERIAL_LOGGER = logger_ref as *const SerialLogger;

        // Install as the global logger. If some other logger has already been
        // registered before this very first call, we don't want to crash the
        // hypervisor over logging, so just ignore the error and still update
        // the max level.
        if log::set_logger(logger_ref).is_ok() {
            log::set_max_level(level);
        } else {
            // Some other logger is already installed; keep SERIAL_LOGGER around
            // so `global_logger()` can still use it directly if desired.
            log::set_max_level(level);
        }
    }
}

/// Serial ports supported by the logger.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SerialPort {
    /// COM1 (0x3F8)
    COM1 = 0x3F8,
    /// COM2 (0x2F8)
    COM2 = 0x2F8,
}

/// The actual logger that implements `log::Log`.
///
/// Made `pub` so that `pub fn global_logger() -> Option<&'static SerialLogger>`
/// doesn’t trip the `private_interfaces` lint.
pub struct SerialLogger {
    port: Mutex<Serial>,
}

impl SerialLogger {
    fn new(port: SerialPort) -> Self {
        Self {
            port: Mutex::new(Serial { port }),
        }
    }
}

impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let vcpu_id = apic_id();
            // lock the serial so we can get &mut Serial
            let mut serial = self.port.lock();
            let _ = writeln!(&mut *serial, "vcpu-{} {}: {}", vcpu_id, record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Low-level serial writer.
struct Serial {
    port: SerialPort,
}

impl Serial {
    fn init(&mut self) {
        let base = self.port as u16;

        // Disable interrupts
        outb(base + UART_OFFSET_INTERRUPT_ENABLE, 0x00);
        // Enable DLAB
        outb(base + UART_OFFSET_LINE_CONTROL, 0x80);
        // Divisor = 3 -> 38400 baud (for 115200 base)
        outb(base + UART_OFFSET_DATA, 0x03);
        outb(base + UART_OFFSET_INTERRUPT_ENABLE, 0x00);
        // 8 bits, no parity, one stop bit
        outb(base + UART_OFFSET_LINE_CONTROL, 0x03);
        // Enable FIFO, clear, 14-byte threshold
        outb(base + UART_OFFSET_FIFO_CONTROL, 0xC7);
        // IRQs enabled, RTS/DSR set
        outb(base + UART_OFFSET_MODEM_CONTROL, 0x0B);
    }

    fn write_byte(&mut self, byte: u8) {
        let base = self.port as u16;
        // Wait until TX empty
        while (inb(base + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
        outb(base + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER, byte);
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.init();
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}

/// Returns the current processor APIC ID so we can tag logs with vCPU id.
fn apic_id() -> u32 {
    x86::cpuid::cpuid!(0x1).ebx >> 24
}

/// Convenience getter if some other part of the hypervisor wants to log manually.
pub fn global_logger() -> Option<&'static SerialLogger> {
    unsafe { if SERIAL_LOGGER.is_null() { None } else { Some(&*SERIAL_LOGGER) } }
}
