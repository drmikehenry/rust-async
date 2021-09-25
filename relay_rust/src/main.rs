use std::io::{Read as _, Write as _};
use async_std::io::{ReadExt, WriteExt};

pub mod error {
    pub type Error = Box<dyn std::error::Error + Send + Sync>;
    pub type Result<T> = std::result::Result<T, Error>;
}

//////////////////////////////////////////////////////////////////////////////
// Single-threaded copy

fn socket_copy(
    mut src: &std::net::TcpStream,
    mut dst: &std::net::TcpStream,
) -> error::Result<()> {
    println!("copy");
    let mut buf: [u8; 1024] = [0; 1024];

    loop {
        let n = src.read(&mut buf[..])?;
        if n == 0 {
            break;
        }
        let mut out = &buf[..n];
        while out.len() > 0 {
            let rv = dst.write(&out[..])?;
            out = &out[rv..];
        }
    }

    dst.shutdown(std::net::Shutdown::Write)?;
    println!("done");

    Ok(())
}

fn socket_relay_single(
    left: std::net::TcpStream,
    right: std::net::TcpStream,
) -> error::Result<()> {
    socket_copy(&left, &right)
}

//////////////////////////////////////////////////////////////////////////////
// Multi-threaded copy

fn socket_relay_threaded(
    left: std::net::TcpStream,
    right: std::net::TcpStream,
) -> error::Result<()> {
    let src = left.try_clone()?;
    let dst = right.try_clone()?;
    let th1: std::thread::JoinHandle<error::Result<()>> =
        std::thread::spawn(move || socket_copy(&src, &dst));

    let src = right.try_clone()?;
    let dst = left.try_clone()?;
    let th2: std::thread::JoinHandle<error::Result<()>> =
        std::thread::spawn(move || socket_copy(&src, &dst));

    th1.join().unwrap()?;
    th2.join().unwrap()?;

    Ok(())
}

//////////////////////////////////////////////////////////////////////////////
// Async copy

async fn socket_copy_async(
    mut src: &async_std::net::TcpStream,
    mut dst: &async_std::net::TcpStream,
) -> error::Result<()> {
    println!("copy");
    let mut buf: [u8; 1024] = [0; 1024];

    loop {
        let n = src.read(&mut buf[..]).await?;
        if n == 0 {
            break;
        }
        let mut out = &buf[..n];
        while out.len() > 0 {
            let rv = dst.write(&out[..]).await?;
            out = &out[rv..];
        }
    }

    dst.shutdown(std::net::Shutdown::Write)?;
    println!("done");

    Ok(())
}

fn socket_relay_async(
    left: std::net::TcpStream,
    right: std::net::TcpStream,
) -> error::Result<()> {
    let left = async_std::net::TcpStream::from(left);
    let right = async_std::net::TcpStream::from(right);

    async_std::task::block_on(async {
        let fut1 = socket_copy_async(&left, &right);
        let fut2 = socket_copy_async(&right, &left);
        let (res1, res2) = futures::join!(fut1, fut2);
        res1?;
        res2?;
        Ok(())
    })
}

//////////////////////////////////////////////////////////////////////////////
// main

fn main() -> error::Result<()> {
    let mut listen_port = 8096;
    let mut connect_port = 8097;

    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        println!("Usage: relay MODE [LISTEN_PORT] [CONNECT_PORT]");
        println!("MODE is one of: single threaded async");
        println!("Defaults:");
        println!("  LISTEN_PORT={}", listen_port);
        println!("  CONNECT_PORT={}", connect_port);
        std::process::exit(1);
    }

    let mode = &args[1];
    let socket_relay = {
        if mode == "single" {
            socket_relay_single
        } else if mode == "threaded" {
            socket_relay_threaded
        } else if mode == "async" {
            socket_relay_async
        } else {
            println!("invalid mode {}", mode);
            std::process::exit(1);
        }
    };

    if args.len() >= 3 {
        listen_port = args[2].parse()?;
    }
    if args.len() >= 4 {
        connect_port = args[3].parse()?;
    }
    println!(
        "Mode={}: LISTEN_PORT={}, CONNECT_PORT={}",
        mode, listen_port, connect_port
    );

    let ip = std::net::Ipv4Addr::from(0x7f000001_u32);

    let listener = std::net::TcpListener::bind((ip, listen_port))?;
    let (server, _) = listener.accept()?;
    let client = std::net::TcpStream::connect((ip, connect_port))?;
    socket_relay(server, client)?;
    Ok(())
}
