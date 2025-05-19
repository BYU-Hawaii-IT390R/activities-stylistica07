# Activity-01: Recursive Directory Scanner with Python

## Enhancement Chosen
**Group files by folder summary** – Shows how many `.txt` files and the total size in KB are in each subfolder after scanning.

## How to Run

1. Create the test files and folders:
   ```
   python setup_files.py
   ```

2. Run the scanner:
   ```
   python scan.py test_root
   ```

## Sample Output

```
Scanning: C:\Users\User\Desktop\git-vs\activities-stylistica07\Activity-01\test_root
Found 20 text files:

File                                      Size (KB)
----------------------------------------------------
docs\file0.txt                                  0.1
docs\file1.txt                                  0.1
docs\file2.txt                                  0.1
docs\file3.txt                                  0.1
docs\file4.txt                                  0.1
docs\subfolder\file0.txt                        0.1
docs\subfolder\file1.txt                        0.1
docs\subfolder\file2.txt                        0.1
docs\subfolder\file3.txt                        0.1
docs\subfolder\file4.txt                        0.1
logs\file0.txt                                  0.1
logs\file1.txt                                  0.1
logs\file2.txt                                  0.1
logs\file3.txt                                  0.1
logs\file4.txt                                  0.1
logs\archive\file0.txt                          0.1
logs\archive\file1.txt                          0.1
logs\archive\file2.txt                          0.1
logs\archive\file3.txt                          0.1
logs\archive\file4.txt                          0.1
----------------------------------------------------
Total size: 2.0 KB

Summary:
  docs/           —  5 files, 0.5 KB
  docs\subfolder/ —  5 files, 0.5 KB
  logs/           —  5 files, 0.5 KB
  logs\archive/   —  5 files, 0.5 KB
