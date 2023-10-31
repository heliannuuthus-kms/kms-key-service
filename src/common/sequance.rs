use std::{
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const EPOCH: u64 = 1519740777809;
const WORKER_ID_BITS: u64 = 5;
const DATA_CENTER_ID_BITS: u64 = 5;
const SEQUENCE_BITS: u64 = 12;

const MAX_WORKER_ID: u64 = (1 << WORKER_ID_BITS) - 1;
const MAX_DATA_CENTER_ID: u64 = (1 << DATA_CENTER_ID_BITS) - 1;
const MAX_SEQUENCE: u64 = (1 << SEQUENCE_BITS) - 1;

const WORKER_ID_SHIFT: u64 = SEQUENCE_BITS;
const DATA_CENTER_ID_SHIFT: u64 = SEQUENCE_BITS + WORKER_ID_BITS;
const TIMESTAMP_LEFT_SHIFT: u64 =
    SEQUENCE_BITS + WORKER_ID_BITS + DATA_CENTER_ID_BITS;

struct Snowflake {
    worker_id: u64,
    data_center_id: u64,
    sequence: Mutex<u64>,
    last_timestamp: Mutex<u64>,
}

impl Snowflake {
    fn new(worker_id: u64, data_center_id: u64) -> Snowflake {
        assert!(
            worker_id <= MAX_WORKER_ID,
            "Worker ID exceeds the maximum value"
        );
        assert!(
            data_center_id <= MAX_DATA_CENTER_ID,
            "Data Center ID exceeds the maximum value"
        );

        Snowflake {
            worker_id,
            data_center_id,
            sequence: Mutex::new(0),
            last_timestamp: Mutex::new(0),
        }
    }

    fn next_id(&self) -> u64 {
        let mut sequence = self.sequence.lock().unwrap();
        let mut last_timestamp = self.last_timestamp.lock().unwrap();

        let mut timestamp = Self::current_timestamp();

        if timestamp < *last_timestamp {
            // Clock moved backwards; wait for the next millisecond
            timestamp = Self::wait_for_next_millisecond(*last_timestamp);
        }

        if timestamp == *last_timestamp {
            // In the same millisecond, increment the sequence
            *sequence = (*sequence + 1) & MAX_SEQUENCE;
            if *sequence == 0 {
                // Sequence overflow, wait for the next millisecond
                timestamp = Self::wait_for_next_millisecond(*last_timestamp);
            }
        } else {
            // New millisecond, reset sequence
            *sequence = 0;
        }

        *last_timestamp = timestamp;

        ((timestamp - EPOCH) << TIMESTAMP_LEFT_SHIFT)
            | (self.data_center_id << DATA_CENTER_ID_SHIFT)
            | (self.worker_id << WORKER_ID_SHIFT)
            | *sequence
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_millis() as u64
    }

    fn wait_for_next_millisecond(last_timestamp: u64) -> u64 {
        let mut timestamp = Self::current_timestamp();
        while timestamp <= last_timestamp {
            thread::sleep(std::time::Duration::from_millis(1));
            timestamp = Self::current_timestamp();
        }
        timestamp
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::Snowflake;
    #[test]
    fn test_generate_id() {
        let snowflake = Arc::new(Snowflake::new(1, 1));

        for _ in 0 .. 100 {
            let snowflake = Arc::clone(&snowflake);
            thread::spawn(move || {
                for _ in 0 .. 10 {
                    let id = snowflake.next_id();
                    println!("Generated ID: {}", id);
                }
            });
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
