use core::arch::asm;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// A simple spinlock for synchronization.
/// Encapsulates unsafe data access behind a mutual exclusion lock.
pub struct Spinlock<T> {
    lock: AtomicBool,
    data: core::cell::UnsafeCell<T>,
}

// Safety: Spinlock is Sync if the underlying data is Send.
unsafe impl<T: Send> Sync for Spinlock<T> {}

impl<T> Spinlock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    /// Acquires the lock, spinning until it is available.
    /// Returns a guard that unlocks the spinlock when dropped.
    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        SpinlockGuard {
            lock: &self.lock,
            data: unsafe {
                // SAFETY:
                // - Why necessary: Accessing the raw pointer inside the UnsafeCell.
                // - Invariants: The atomic boolean `lock` has been set to `true`, ensuring
                //   mutual exclusion. No other thread or CPU core can access this data until
                //   the guard is dropped.
                // - Soundness: Exclusive reference is guaranteed by the atomic acquisition.
                &mut *self.data.get()
            },
        }
    }
}

pub struct SpinlockGuard<'a, T> {
    lock: &'a AtomicBool,
    data: &'a mut T,
}

impl<T> core::ops::Deref for SpinlockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T> core::ops::DerefMut for SpinlockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T> Drop for SpinlockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.store(false, Ordering::Release);
    }
}

/// Represents an x86_64 serial port (specifically COM1 at 0x3F8).
pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initializes the serial port.
    pub fn init(&self) {
        unsafe {
            // SAFETY:
            // - Why necessary: Port I/O instructions (outb) are inherently unsafe as they write
            //   directly to hardware devices.
            // - Invariants: The port address must be a valid system serial port.
            // - Soundness: We configure COM1 using standard initialization sequences. No other
            //   subsystems are yet mapping or interacting with these ports.
            outb(self.port + 1, 0x00); // Disable all interrupts
            outb(self.port + 3, 0x80); // Enable DLAB (set divisor)
            outb(self.port + 0, 0x03); // Set divisor to 3 (38400 baud)
            outb(self.port + 1, 0x00); // High byte of divisor
            outb(self.port + 3, 0x03); // 8 bits, no parity, one stop bit
            outb(self.port + 2, 0xC7); // Enable FIFO, clear, 14-byte threshold
            outb(self.port + 4, 0x0B); // RTS/DSR set
        }
    }

    /// Checks if the transmit buffer is empty (bit 5 of Line Status Register).
    fn is_transmit_empty(&self) -> bool {
        unsafe {
            // SAFETY:
            // - Why necessary: Reading from the serial port status register (inb).
            // - Invariants: Valid port mapping.
            // - Soundness: Safe register read.
            (inb(self.port + 5) & 0x20) != 0
        }
    }

    /// Sends a single byte over the serial port.
    pub fn send(&self, byte: u8) {
        unsafe {
            // SAFETY:
            // - Why necessary: Writing a byte to the serial data register (outb).
            // - Invariants: Port must be initialized.
            // - Soundness: Safe register write.
            outb(self.port, byte);
        }
    }

    /// Writes a string slice to the serial port.
    pub fn write_string(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.send(b'\r');
            }
            self.send(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

// Assembly port I/O wrappers.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY:
    // - Why necessary: `in` assembly instruction reads direct CPU I/O space.
    // - Invariants: Port number must map to a valid physical device.
    // - Soundness: The port is controlled and bounded by the caller.
    asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY:
    // - Why necessary: `out` assembly instruction writes directly to CPU I/O space.
    // - Invariants: Port number must map to a valid physical device.
    // - Soundness: Safe write to valid I/O register.
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

// Global COM1 serial port writer.
pub static SERIAL1: Spinlock<SerialPort> = Spinlock::new(SerialPort::new(0x3F8));

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // We lock the serial port to prevent interleaved output.
    let mut serial = SERIAL1.lock();
    serial.write_fmt(args).unwrap();
}

/// Prints to the serial console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::drivers::serial::_print(format_args!($($arg)*));
    };
}

/// Prints to the serial console, with a newline.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Compile-time verbosity switch for low-level kernel tracing.
///
/// When `false`, `dbg_println!` expands to nothing, keeping the boot log
/// deterministic and readable (Phase 9: deterministic boot). Flip to `true`
/// to recover the verbose per-syscall / per-spawn diagnostics used during
/// bring-up.
pub const DEBUG: bool = false;

/// Like `println!`, but only emits when [`DEBUG`] is `true`. Used for
/// high-frequency diagnostics (syscall entry/exit, GDT dumps, task wiring)
/// that would otherwise flood the serial console.
#[macro_export]
macro_rules! dbg_println {
    ($($arg:tt)*) => {
        if $crate::drivers::serial::DEBUG {
            $crate::println!($($arg)*);
        }
    };
}
