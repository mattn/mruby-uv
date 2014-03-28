#include "mrb_uv.h"


static void
mrb_uv_dlfree(mrb_state *mrb, void *p)
{
  if (p) {
    uv_dlclose((uv_lib_t*)p);
    mrb_free(mrb, p);
  }
}

static const struct mrb_data_type dl_type = {
  "uv_dl", mrb_uv_dlfree
};

mrb_value
mrb_uv_dlopen(mrb_state *mrb, char const *name)
{
  mrb_value ret = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_DATA, mrb_class_get_under(mrb, mrb_class_get(mrb, "UV"), "DL")));
  uv_lib_t *lib = (uv_lib_t*)mrb_malloc(mrb, sizeof(uv_lib_t));
  int err;

  DATA_TYPE(ret) = &dl_type;
  DATA_PTR(ret) = lib;
  err = uv_dlopen(name, lib);
  if (err == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_dlerror(lib));
  }

  return ret;
}

void*
mrb_uv_dlsym(mrb_state *mrb, mrb_value dl, char const *name)
{
  int err;
  void *p;
  uv_lib_t *lib;
  Data_Get_Struct(mrb, dl, &dl_type, lib);
  if (!lib) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "getting symbol from closed libraray");
  }
  err = uv_dlsym(lib, name, &p);
  if(err == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, uv_dlerror(lib));
  }
  return p;
}

void
mrb_uv_dlclose(mrb_state *mrb, mrb_value dl)
{
  uv_lib_t *lib;
  Data_Get_Struct(mrb, dl, &dl_type, lib);
  if (lib) {
    uv_dlclose(lib);
    mrb_free(mrb, DATA_PTR(dl));
    DATA_PTR(dl) = NULL;
  }
}

static mrb_value
mrb_f_uv_dlopen(mrb_state *mrb, mrb_value self)
{
  char *z;
  mrb_get_args(mrb, "z", &z);
  mrb_value ret = mrb_uv_dlopen(mrb, z);
  DATA_TYPE(self) = DATA_TYPE(ret);
  DATA_PTR(self) = DATA_PTR(ret);
  DATA_TYPE(ret) = NULL;
  DATA_PTR(ret) = NULL;
  return self;
}

static mrb_value
mrb_f_uv_dlclose(mrb_state *mrb, mrb_value self)
{
  mrb_uv_dlclose(mrb, self);
  return self;
}

static mrb_value
mrb_f_uv_dlsym(mrb_state *mrb, mrb_value self)
{
  char *z;
  mrb_get_args(mrb, "z", &z);
  return mrb_voidp_value(mrb, mrb_uv_dlsym(mrb, self, z));
}

void
mrb_mruby_uv_gem_init_dl(mrb_state *mrb, struct RClass *UV)
{
  struct RClass *class_uv_dl;

  class_uv_dl = mrb_define_class_under(mrb, UV, "DL", mrb->object_class);
  MRB_SET_INSTANCE_TT(class_uv_dl, MRB_TT_DATA);
  mrb_define_method(mrb, class_uv_dl, "initialize", mrb_f_uv_dlopen, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, class_uv_dl, "close", mrb_f_uv_dlclose, MRB_ARGS_NONE());
  mrb_define_method(mrb, class_uv_dl, "sym", mrb_f_uv_dlsym, MRB_ARGS_REQ(1));
}