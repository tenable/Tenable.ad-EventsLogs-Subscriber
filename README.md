[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202-blue)](https://github.com/tenable/Tenable.ad-EventsLogs-Subscriber/blob/master/LICENSE.txt)
![PRs not allowed](https://img.shields.io/badge/PRs-notallowed-brightgreen.svg)

## Tenable.ad IOA event logs listener

Tenable.ad IOA event logs listener, developed in **Rust**, is part of the **Tenable.ad IOA module**.
It listens to **event logs** coming from channels declared in `TenableADEventsListenerConfiguration.json` configuration file, and filters those with declared event identifiers and provider names. The listener uses **EvtSubscribe Windows API** for this purpose.

The listener **buffers** event logs during time intervals and **writes them to a file** regularly. The file can be compressed or not.

![Event logs listener GPO](/images/gpo.png "Event logs listener GPO")

The listener also lowers impacts on the side of the domain controllers with the help of specific mechanisms (explicit CPU/RAM limitations, throttling, etc).

![Event logs listener running](/images/run.png "Event logs listener running")

## Build

```
cargo build --release
```

## Run

```bash
.\\Register-TenableADEventsListener.exe -t 15 -p 'C:\file.gz' -g
```

## Help

```bash
.\\Register-TenableADEventsListener.exe -h
```

## Arguments

The following command launches an event listener, which forwards each received event to an internal memory
buffer. The listener flushed its buffer to the disk periodically.

**USAGE**:
```
    Register-TenableADEventsListener.exe [OPTIONS] --EventLogFilePath <EVENT_LOG_FILE_PATH> --TimerDurationSeconds <TIMER_DURATION_SECONDS>
```

**OPTIONS**:  
```
    -b, --MaxBufferSizeBytes <MAX_BUFFER_SIZE_BYTES>
            The maximum buffer size in bytes [default: 524288000]

    -d, --DurationLeapMilliSeconds <DURATION_LEAP>
            The duration leap to adjust events logs consumption throughput, in milliseconds
            [default: 10]

    -g, --EnableGzip
            Whether GZip compression is enabled

    -h, --help
            Print help information

    -p, --EventLogFilePath <EVENT_LOG_FILE_PATH>
            The file where events are written

    -r, --CpuRate <CPU_RATE>
            Control the CPU rate of the process (does not work on Windows Sever 2008R2 and below)
            [default: 20]

    -s, --MaxThroughput <MAX_THROUGHPUT>
            The maximum handled throughput, in event logs per second [default: 1500]

    -t, --TimerDurationSeconds <TIMER_DURATION_SECONDS>
            The interval between each file write

    -w, --Preview
            Enable preview features

    --UseXmlEventRender
            Use the legacy XML event rendering method for listeners. Although slower than the current values-based approach, it provides greater stability. This option is disabled by default.
```

## Contribution

Tenable does not allow any public contribution.
You can report issues to Tenable by reaching out to your support contact.

## License

The project is licensed under Apache 2.0