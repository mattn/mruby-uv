#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/data.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include <mrb_uv.h>

static void
p(mrb_state *mrb, mrb_value obj) {
  obj = mrb_funcall(mrb, obj, "inspect", 0);
  fwrite(RSTRING_PTR(obj), RSTRING_LEN(obj), 1, stdout);
  putc('\n', stdout);
}

int
main(int argc, char **argv) {
  if(argc != 2) {
    fprintf(stdout, "Usage: runner inputfile\n");
    exit(1);
  }

  char *input_file = argv[1];
  FILE *fp = fopen(input_file, "r");
  if(fp == NULL) {
    fprintf(stderr, "Error opening file: '%s' - %s\n", input_file, strerror(errno));
    exit(2);
  }

  mrb_state* mrb = mrb_open();
  mrb_uv_init(mrb);
  mrbc_context *c = mrbc_context_new(mrb);
  mrbc_filename(mrb, c, input_file);
  mrb_value v = mrb_load_file_cxt(mrb, fp, c);
  mrbc_context_free(mrb, c);
  if (mrb->exc) {
    if (!mrb_undef_p(v)) {
      p(mrb, mrb_obj_value(mrb->exc));
    }
  }
  fclose(fp);
  return 0;
}
