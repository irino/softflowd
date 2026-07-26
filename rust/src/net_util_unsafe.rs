use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::ffi::CString;

#[cfg(target_os = "linux")]
pub fn bind_socket_to_device(socket: &UdpSocket, device: &str) -> std::io::Result<()> {
    let device_name = CString::new(device).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device_name.as_ptr() as *const libc::c_void,
            device_name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
