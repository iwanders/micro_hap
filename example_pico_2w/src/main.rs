#![no_std]
#![no_main]

use core::marker::Sized;

use embassy_executor::Spawner;
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    example_pico_2w::main(spawner).await;
}
