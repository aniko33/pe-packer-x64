# Table Of Content

- [Note](#note)
- [Compile](#compile)
- [Usage](#usage)
- [Why this repository](#why-this-repository)
- [Sources](#resources)

# Note

**This is a template for a packer**, you can **<ins>modify it to your own use case</ins>**. at the moment can only *load in memory and run PEs*

# Compile

```bash
cmake -B build
cd build
make # output: main
```

# Usage

```bash
./main file_to_load.exe
```

# Why this repository

I decided to take the x86 packer from the [wiredriver tutorial](https://wirediver.com/tutorial-writing-a-pe-packer-intro/) and make it x64 to understand what the differences are between an x86 and x64 PE

# Resources

- https://0xrick.github.io/win-internals/pe1/
- https://wirediver.com/tutorial-writing-a-pe-packer-intro/
- https://github.com/NUL0x4C/AtomPePacker