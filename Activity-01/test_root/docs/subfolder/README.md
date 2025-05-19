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
Scanning: /full/path/to/test_root
Found 20 text files:

File                                     Size (KB)
----------------------------------------------------
docs/file0.txt                               0.1
docs/file1.txt                               0.1
logs/file2.txt                               0.1
...

----------------------------------------------------
Total size: 18.5 KB

Summary:
  docs/             —  5 files, 4.6 KB
  logs/             —  5 files, 4.6 KB
  docs/subfolder/   —  5 files, 4.6 KB
  logs/archive/     —  5 files, 4.6 KB
```
