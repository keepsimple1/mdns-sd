@echo off
:loop
echo Running cargo test...
cargo test --release --test mdns_test
echo.
echo Press Ctrl+C to stop or wait for the next run...
timeout /t 1 /nobreak >nul
goto loop