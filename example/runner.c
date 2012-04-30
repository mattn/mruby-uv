#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <compile.h>
#include <mrb_uv.h>

void print_usage()
{
  fprintf(stdout, "Usage: runner inputfile\n");
}

int main(int argc, char **argv)
{
  if(argc != 2)
  {
    print_usage();
    exit(1);
  }

  char *input_file = argv[1];

  FILE *fp = fopen(input_file, "r");
  if(fp == NULL)
  {
    fprintf(stderr, "Error opening file: '%s' - %s\n", input_file, strerror(errno));
    exit(2);
  }

  char *code = NULL;
  char buffer[1024];
  int code_size = 0;
  do
  {
    int read_bytes = fread(buffer, sizeof(char), 1024, fp);
    code = realloc(code, code_size + read_bytes);
    memcpy(code+code_size, buffer, read_bytes);
    code_size += read_bytes;
  } while(!feof(fp));

  code = realloc(code, code_size + 1);
  code[code_size] = 0;

  if(fclose(fp) != 0)
  {
    fprintf(stderr, "Error closing file: '%s' - %s\n", input_file, strerror(errno));
    exit(3);
  }

  mrb_state* mrb = mrb_open();
  mrb_uv_init(mrb);

  struct mrb_parser_state* st = mrb_parse_string(mrb, code);
  free(code);

  int n = mrb_generate_code(mrb, st->tree);

  mrb_pool_close(st->pool);
  mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_nil_value());

  return 0;
}
