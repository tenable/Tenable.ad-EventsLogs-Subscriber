use std::fmt::{Display, Formatter};
use std::time::SystemTime;

pub struct FileSharingMetrics {
    nb_files_sent: i64,
    file_generation: i64,
    last_file_sent_at: Option<SystemTime>,
    avg_file_size_in_bytes: i64,
}

impl Default for FileSharingMetrics {
    fn default() -> Self {
        Self {
            nb_files_sent: 0,
            file_generation: 0,
            last_file_sent_at: None,
            avg_file_size_in_bytes: 0,
        }
    }
}

impl Display for FileSharingMetrics {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "{} file(s) shared since started (average file size: {} bytes - last file sent: {})",
            self.nb_files_sent, self.avg_file_size_in_bytes,
            if self.last_file_sent_at.is_some() {
                format!("{} second(s) ago", self.last_file_sent_at.unwrap().elapsed().unwrap().as_secs())
            } else {
                "Not yet".to_string()
            }
        );
        fmt.write_str(&str)?;
        Ok(())
    }
}

impl FileSharingMetrics {
    pub fn add_file_sent_size(&mut self, size: i64) {
        self.nb_files_sent += 1;
        self.last_file_sent_at = Some(SystemTime::now());
        let avg_delta: i64 = (size - self.avg_file_size_in_bytes) / self.file_generation;
        self.avg_file_size_in_bytes += avg_delta;
    }

    pub fn get_current_generation(&self) -> i64 {
        return self.file_generation;
    }

    pub fn increment_file_generation(&mut self) {
        self.file_generation += 1;
    }

    pub fn reset_files_sent(&mut self) {
        self.nb_files_sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_be_able_to_dump_metrics() {
        // Arrange
        let metrics = FileSharingMetrics {
            nb_files_sent: 100,
            file_generation: 500,
            avg_file_size_in_bytes: 12345,
            last_file_sent_at: Some(SystemTime::now()),
        };

        // Act
        let output = metrics.to_string();

        // Assert
        assert_eq!(
            "100 file(s) shared since started (average file size: 12345 bytes - last file sent: 0 second(s) ago)",
            output
        );
    }

    #[test]
    fn it_should_properly_calculate_avg_size_file() {
        // Arrange
        let mut metrics = FileSharingMetrics::default();
        let file_sent_size = [100, 200, 1000, 5, 9, 2000];
        let sum: i32 = file_sent_size.iter().sum();
        let len: i32 = file_sent_size.len() as i32;
        let expected_avg_size: i32 = sum / len;
        for size in file_sent_size {
            metrics.increment_file_generation();
            metrics.add_file_sent_size(size as i64);
        }

        // Act
        let output = metrics.to_string();

        // Assert
        assert_eq!(
            format!(
                "{} file(s) shared since started (average file size: {} bytes - last file sent: 0 second(s) ago)",
                file_sent_size.len(), expected_avg_size,
            ),
            output
        );
    }
}