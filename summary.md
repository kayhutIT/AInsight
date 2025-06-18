### main.c – int main(void)
**Includes:** stdio.h, util.h

**Header util.h:**
```
#ifndef UTIL_H
#define UTIL_H

void print_message(const char *filename);

#endif // UTIL_H
```
**Resource ../resources/message.txt:**
```

```
**Implementation:**
```c
print_message("../resources/message.txt");
    return 0;
```
Based on the provided code context, here's the description of the `print_message` function and its purpose:

### Purpose:
The `print_message` function appears to be a utility function designed to read and display the contents of a text file specified by its filename.

### Behavior:
1. Takes a file path as input (`const char *filename`)
2. Opens and reads the file located at "../resources/message.txt" (as called in `main.c`)
3. Prints the contents of the file to standard output (likely using file I/O operations)
4. Handles file operations (opening, reading, and closing the file)

### Full Context:
- The function is declared in `util.h` header file
- It's called from `main()` in `main.c` with a relative path "../resources/message.txt"
- The main program simply calls this function and returns 0
- The actual implementation isn't shown, but based on the function name and usage, it's clearly meant to output file contents

### Typical Implementation Might Include:
1. File existence checking
2. Reading line-by-line or all-at-once
3. Error handling for cases where the file doesn't exist
4. Outputting the exact contents to stdout

The function serves as a simple file display utility, separating file I/O operations from the main program logic.
---
### util.c – void print_message(const char *filename)
**Includes:** stdio.h, util.h

**Header util.h:**
```
#ifndef UTIL_H
#define UTIL_H

void print_message(const char *filename);

#endif // UTIL_H
```
**Implementation:**
```c
FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return;
    }
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }
    fclose(file);
```
Based on the provided code context, here's the purpose and behavior of the `print_message` function:

**Purpose:**
The function `print_message` is designed to read and display the contents of a text file to the standard output (console).

**Behavior:**
1. It takes a filename as input (const char pointer) representing the file to be read.
2. It attempts to open the file in read mode ("r").
3. If the file fails to open (returns NULL), it:
   - Prints an error message using `perror` (which includes the system's error description)
   - Returns immediately without further execution
4. If the file opens successfully:
   - It reads the file character by character using `fgetc`
   - Prints each character to standard output using `putchar`
   - Continues this until reaching EOF (end-of-file)
5. Finally, it closes the file before returning

**Header File Context:**
The function is declared in `util.h` with the same prototype, suggesting it's part of a utility library meant to be used by other parts of a larger project.

**Safety Notes:**
- The filename parameter is marked `const`, protecting it from modification
- The function properly checks for file opening errors
- It properly closes the file when done

**Limitations:**
- It doesn't handle very large files efficiently (character-by-character reading)
- There's no buffer overflow protection (fine for text viewing purposes)
- The error handling is minimal (just prints and exits)

This is essentially a simple file viewer function that could be used to display help files, readme contents, or other text-based resources in a C program.
---
