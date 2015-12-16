/*
  +----------------------------------------------------------------------+
  | ext/test_helper                                                      |
  | An extension for the PHP Interpreter to ease testing of PHP code.    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2009-2013 Sebastian Bergmann. All rights reserved.     |
  +----------------------------------------------------------------------+
  | Redistribution and use in source and binary forms, with or without   |
  | modification, are permitted provided that the following conditions   |
  | are met:                                                             |
  |                                                                      |
  |  * Redistributions of source code must retain the above copyright    |
  |    notice, this list of conditions and the following disclaimer.     |
  |                                                                      |
  |  * Redistributions in binary form must reproduce the above copyright |
  |    notice, this list of conditions and the following disclaimer in   |
  |    the documentation and/or other materials provided with the        |
  |    distribution.                                                     |
  |                                                                      |
  |  * Neither the name of Sebastian Bergmann nor the names of his       |
  |    contributors may be used to endorse or promote products derived   |
  |    from this software without specific prior written permission.     |
  |                                                                      |
  | THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS  |
  | "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT    |
  | LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS    |
  | FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE       |
  | COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,  |
  | INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, |
  | BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;     |
  | LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER     |
  | CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT   |
  | LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN    |
  | ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE      |
  | POSSIBILITY OF SUCH DAMAGE.                                          |
  +----------------------------------------------------------------------+
  | Author: Johannes Schlüter <johannes@schlueters.de>                   |
  |         Scott MacVicar <scott@macvicar.net>                          |
  |         Sebastian Bergmann <sb@sebastian-bergmann.de>                |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_test_helpers.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_extensions.h"
#include "Zend/zend_compile.h"

#ifdef PHP_WIN32
#   define PHP_TEST_HELPERS_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_TEST_HELPERS_API __attribute__ ((visibility("default")))
#else
#   define PHP_TEST_HELPERS_API
#endif

# define ZEND_USER_OPCODE_HANDLER_ARGS zend_execute_data *execute_data
# define ZEND_USER_OPCODE_HANDLER_ARGS_PASSTHRU execute_data

#define ZEND_VM_CONTINUE()         return 0

#define ZEND_VM_NEXT_OPCODE_CHECK_EXCEPTION() \
	opline = EX(opline) + 1; \
	ZEND_VM_CONTINUE()

#define HANDLE_EXCEPTION() \
	EX(opline) = opline; \
	ZEND_VM_CONTINUE()

static user_opcode_handler_t old_new_handler = NULL;
static user_opcode_handler_t old_exit_handler = NULL;
static int test_helpers_module_initialized = 0;

typedef struct {
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
} user_handler_t;

ZEND_BEGIN_MODULE_GLOBALS(test_helpers)
	user_handler_t new_handler;
	user_handler_t exit_handler;
	zend_long	   copts;
ZEND_END_MODULE_GLOBALS(test_helpers)

ZEND_DECLARE_MODULE_GLOBALS(test_helpers)

static void test_helpers_free_handler(zend_fcall_info *fci) /* {{{ */
{
	ZVAL_UNDEF(&fci->function_name);
	if (fci->object) {
		zend_object_std_dtor(fci->object);
		fci->object = NULL;
	}
}
/* }}} */

static int pth_new_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */
{
	zval retval, arg;
	zend_string *retval_zstr;
	zend_class_entry *old_ce, *new_ce;
	zend_execute_data *execute_data = EG(current_execute_data);
	const zend_op *opline = execute_data->opline;

	if (Z_TYPE(THG(new_handler).fci.function_name) == IS_UNDEF) {
		if (old_new_handler) {
			return old_new_handler(ZEND_USER_OPCODE_HANDLER_ARGS_PASSTHRU);
		}
		return ZEND_USER_OPCODE_DISPATCH;
	}
	if (opline->op1_type == IS_CONST) {
		old_ce = CACHED_PTR(Z_CACHE_SLOT_P(EX_CONSTANT(opline->op1)));
		if (old_ce == NULL) {
			old_ce = zend_fetch_class_by_name(Z_STR_P(EX_CONSTANT(opline->op1)), EX_CONSTANT(opline->op1) + 1, ZEND_FETCH_CLASS_DEFAULT | ZEND_FETCH_CLASS_EXCEPTION);
			if (old_ce == NULL) {
				ZEND_VM_NEXT_OPCODE_CHECK_EXCEPTION();
			}
		}
	} else if (opline->op1_type == IS_UNUSED) {
		old_ce = zend_fetch_class(NULL, opline->op1.num);
		if (old_ce == NULL) {
			HANDLE_EXCEPTION();
		}
	} else  {
		old_ce = Z_CE_P(EX_VAR(opline->op1.var));
	}

	ZVAL_STRINGL(&arg, ZSTR_VAL(old_ce->name), ZSTR_LEN(old_ce->name));

	zend_fcall_info_argn(&THG(new_handler).fci, 1, &arg);
	zend_fcall_info_call(&THG(new_handler).fci, &THG(new_handler).fcc, &retval, NULL);
	zend_fcall_info_args_clear(&THG(new_handler).fci, 1);

	convert_to_string_ex(&retval);
	retval_zstr = zval_get_string(&retval);
	if ((new_ce = zend_lookup_class(retval_zstr)) == NULL) {
		if (!EG(exception)) {
			zend_throw_exception_ex(zend_exception_get_default(), -1, "Class %s does not exist", Z_STRVAL(retval));
		}
		zval_ptr_dtor(&arg);
		zval_ptr_dtor(&retval);
		zend_string_release(retval_zstr);

		return ZEND_USER_OPCODE_CONTINUE;
	}
	zval_ptr_dtor(&arg);
	zval_ptr_dtor(&retval);
	zend_string_release(retval_zstr);

	if (opline->op1_type == IS_CONST) {
		CACHE_PTR(Z_CACHE_SLOT_P(EX_CONSTANT(opline->op1)), new_ce);
	}

	if (old_new_handler) {
		return old_new_handler(ZEND_USER_OPCODE_HANDLER_ARGS_PASSTHRU);
	}
	return ZEND_USER_OPCODE_DISPATCH;
}
/* }}} */

static int pth_exit_handler(ZEND_OPCODE_HANDLER_ARGS) /* {{{ */
{
	zval *msg = NULL;
	zend_execute_data *execute_data = EG(current_execute_data);
	const zend_op *opline = execute_data->opline;
	zval retval;
	zend_free_op free_op;


	if (Z_TYPE(THG(exit_handler).fci.function_name) == IS_UNDEF) {
		if (old_exit_handler) {
			return old_exit_handler(ZEND_USER_OPCODE_HANDLER_ARGS_PASSTHRU);
		}
		return ZEND_USER_OPCODE_DISPATCH;
	}

	if ((msg = zend_get_zval_ptr(opline->op1_type, &opline->op1, execute_data, &free_op, 0)) != NULL) {
		zend_fcall_info_argn(&THG(exit_handler).fci, 1, msg);
	}

	zend_fcall_info_call(&THG(exit_handler).fci, &THG(exit_handler).fcc, &retval, NULL);
	zend_fcall_info_args_clear(&THG(exit_handler).fci, 1);

	if(UNEXPECTED(Z_TYPE(retval) == IS_UNDEF)) {
		EX(opline)++;
		return ZEND_USER_OPCODE_CONTINUE;
	}

	convert_to_boolean(&retval);
	if (Z_TYPE(retval) == IS_TRUE) {
		zval_ptr_dtor(&retval);
		if (old_exit_handler) {
			return old_exit_handler(ZEND_USER_OPCODE_HANDLER_ARGS_PASSTHRU);
		}
		return ZEND_USER_OPCODE_DISPATCH;
	} else {
		zval_ptr_dtor(&retval);
		EX(opline)++;
		return ZEND_USER_OPCODE_CONTINUE;
	}
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
static PHP_MINIT_FUNCTION(test_helpers)
{
	if (test_helpers_module_initialized) {
		/* This should never happen as it is handled by the module loader, but let's play safe */
		php_error_docref(NULL, E_WARNING, "test_helpers had already been initialized! Either load it as regular PHP extension or zend_extension");
		return FAILURE;
	}

	old_new_handler = zend_get_user_opcode_handler(ZEND_NEW);
	zend_set_user_opcode_handler(ZEND_NEW, pth_new_handler);

	old_exit_handler = zend_get_user_opcode_handler(ZEND_EXIT);
	zend_set_user_opcode_handler(ZEND_EXIT, pth_exit_handler);

	test_helpers_module_initialized = 1;

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
static PHP_RINIT_FUNCTION(test_helpers)
{

	THG(copts) = CG(compiler_options);

	CG(compiler_options) |= ZEND_COMPILE_HANDLE_OP_ARRAY |
		ZEND_COMPILE_NO_CONSTANT_SUBSTITUTION |
		ZEND_COMPILE_IGNORE_INTERNAL_FUNCTIONS |
		ZEND_COMPILE_IGNORE_USER_FUNCTIONS |
		ZEND_COMPILE_GUARDS;

	return SUCCESS;
}
/* }}} */

/* {{{ */
static inline int php_test_helpers_destroy_user_function(zval *zv) {
    zend_function *function = Z_PTR_P(zv);

    if (function->type == ZEND_USER_FUNCTION) {
        return ZEND_HASH_APPLY_REMOVE;
    }

    return ZEND_HASH_APPLY_KEEP;
} /* }}} */

/* {{{ */
static inline int php_test_helpers_destroy_user_functions(zval *zv) {
    zend_class_entry *ce = Z_PTR_P(zv);

    zend_hash_apply(&ce->function_table, php_test_helpers_destroy_user_function);

    if (ce->type == ZEND_USER_CLASS) {
        return ZEND_HASH_APPLY_REMOVE;
    }

    return ZEND_HASH_APPLY_KEEP;
} /* }}} */

/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
static PHP_RSHUTDOWN_FUNCTION(test_helpers)
{
	CG(compiler_options) = THG(copts);

	test_helpers_free_handler(&THG(new_handler).fci);
	test_helpers_free_handler(&THG(exit_handler).fci);

	zend_hash_apply(CG(function_table), php_test_helpers_destroy_user_function);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
static PHP_MINFO_FUNCTION(test_helpers)
{
	char *conflict_text;

	if (pth_new_handler != zend_get_user_opcode_handler(ZEND_NEW)) {
		conflict_text = "Yes. The work-around was NOT enabled. Please make sure test_helpers was loaded as zend_extension AFTER conflicting extensions like Xdebug!";
	} else if (old_new_handler != NULL) {
		conflict_text = "Yes, work-around enabled";
	} else {
		conflict_text = "No conflict detected";
	}
	php_info_print_table_start();
	php_info_print_table_header(2, "test_helpers support", "enabled");
	php_info_print_table_row(2, "Conflicting extension found", conflict_text);
	php_info_print_table_end();
}
/* }}} */

static void overload_helper(user_opcode_handler_t op_handler, int opcode, user_handler_t *handler, INTERNAL_FUNCTION_PARAMETERS) /* {{{ */
{
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "f", &fci, &fcc) == FAILURE) {
		return;
	}

	if (op_handler != zend_get_user_opcode_handler(opcode)) {
		php_error_docref(NULL, E_WARNING, "A conflicting extension was detected. Make sure to load test_helpers as zend_extension after other extensions");
	}

	test_helpers_free_handler(&handler->fci);

	handler->fci = fci;
	handler->fcc = fcc;
	Z_TRY_ADDREF(handler->fci.function_name);
	if (handler->fci.object) {
		GC_REFCOUNT(handler->fci.object)++;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool set_new_overload(callback cb)
   Register a callback, called on instantiation of a new object */
static PHP_FUNCTION(set_new_overload)
{
	overload_helper(pth_new_handler, ZEND_NEW, &THG(new_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool set_exit_overload(callback cb)
   Register a callback, called on exit()/die() */
static PHP_FUNCTION(set_exit_overload)
{
	overload_helper(pth_exit_handler, ZEND_EXIT, &THG(exit_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

static void unset_overload_helper(user_handler_t *handler, INTERNAL_FUNCTION_PARAMETERS) /* {{{ */
{
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	test_helpers_free_handler(&handler->fci);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool unset_new_overload()
   Remove the current new handler */
static PHP_FUNCTION(unset_new_overload)
{
	unset_overload_helper(&THG(new_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

/* {{{ proto bool unset_exit_overload()
   Remove the current exit handler */
static PHP_FUNCTION(unset_exit_overload)
{
	unset_overload_helper(&THG(exit_handler), INTERNAL_FUNCTION_PARAM_PASSTHRU);
}
/* }}} */

static int pth_rename_function_impl(HashTable *table, char *orig, size_t orig_len, char *new, size_t new_len) /* {{{ */
{
	zend_function *func;
	zend_internal_function *internal_tmp;

	if ((func = zend_hash_str_find_ptr(table, orig, orig_len)) == NULL) {
		php_error_docref(NULL, E_WARNING, "%s(%s, %s) failed: %s does not exist!",
						get_active_function_name(),
						orig,  new, orig);
		return FAILURE;
	}

	if (zend_hash_str_exists(table, new, new_len)) {
		php_error_docref(NULL, E_WARNING, "%s(%s, %s) failed: %s already exists!",
							get_active_function_name(),
							orig,  new, new);
		return FAILURE;
	}

	if (func->type == ZEND_INTERNAL_FUNCTION) {
		internal_tmp = (zend_internal_function*) pemalloc(sizeof(zend_internal_function), 1);
		memcpy(internal_tmp, func, sizeof(zend_internal_function));
		func = (zend_function*) internal_tmp;
	} else {
		function_add_ref(func);
	}

	if (zend_hash_str_add_ptr(table, new, new_len, func) == NULL) {
		php_error_docref(NULL, E_WARNING, "%s() failed to insert %s into CG(function_table)", get_active_function_name(), new);
		return FAILURE;
	}

	if (zend_hash_str_del(table, orig, orig_len) == FAILURE) {
		php_error_docref(NULL, E_WARNING, "%s() failed to remove %s from function table", get_active_function_name(), orig);
		zend_hash_str_del(table, new, new_len);
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

static int pth_rename_function(HashTable *table, char *orig, size_t orig_len, char *new, size_t new_len) /* {{{ */
{
	char *lower_orig, *lower_new;
	int success;

	lower_orig = zend_str_tolower_dup(orig, orig_len);
	lower_new = zend_str_tolower_dup(new, new_len);

	success = pth_rename_function_impl(table, lower_orig, orig_len, lower_new, new_len);

	efree(lower_orig);
	efree(lower_new);

	return success;
}
/* }}} */

/* {{{ proto bool rename_method(string class name, string orig_method_name, string new_method_name)
   Rename a method inside a class. The method whil remain partof the same class */
static PHP_FUNCTION(rename_method)
{
	zend_class_entry *ce = NULL;
	char *orig_fname, *new_fname;
	size_t orig_fname_len, new_fname_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Css", &ce, &orig_fname, &orig_fname_len, &new_fname, &new_fname_len) == FAILURE) {
		return;
	}

	if (SUCCESS == pth_rename_function(&ce->function_table, orig_fname, orig_fname_len, new_fname, new_fname_len)) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto bool rename_function(string orig_func_name, string new_func_name)
   Rename a function from its original to a new name. This is mainly useful in
   unittest to stub out untested functions */
static PHP_FUNCTION(rename_function)
{
	char *orig_fname, *new_fname;
	size_t orig_fname_len, new_fname_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &orig_fname, &orig_fname_len, &new_fname, &new_fname_len) == FAILURE) {
		return;
	}

	if (SUCCESS == pth_rename_function(CG(function_table), orig_fname, orig_fname_len, new_fname, new_fname_len)) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ arginfo */
/* {{{ unset_new_overload */
ZEND_BEGIN_ARG_INFO(arginfo_unset_new_overload, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ unset_exit_overload */
ZEND_BEGIN_ARG_INFO(arginfo_unset_exit_overload, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ set_new_overload */
ZEND_BEGIN_ARG_INFO(arginfo_set_new_overload, 0)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ rename_method */
ZEND_BEGIN_ARG_INFO(arginfo_rename_method, 0)
	ZEND_ARG_INFO(0, class_name)
	ZEND_ARG_INFO(0, orig_method_name)
	ZEND_ARG_INFO(0, new_method_name)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ rename_function */
ZEND_BEGIN_ARG_INFO(arginfo_rename_function, 0)
	ZEND_ARG_INFO(0, orig_func_name)
	ZEND_ARG_INFO(0, new_func_name)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ set_exit_overload */
ZEND_BEGIN_ARG_INFO(arginfo_set_exit_overload, 0)
	ZEND_ARG_INFO(0, "callback")
ZEND_END_ARG_INFO()
/* }}} */

/* }}} */

/* {{{ test_helpers_functions[]
 */
static const zend_function_entry test_helpers_functions[] = {
	PHP_FE(unset_new_overload, arginfo_unset_new_overload)
	PHP_FE(set_new_overload, arginfo_set_new_overload)
	PHP_FE(unset_exit_overload, arginfo_unset_exit_overload)
	PHP_FE(set_exit_overload, arginfo_set_exit_overload)
	PHP_FE(rename_method, arginfo_rename_method)
	PHP_FE(rename_function, arginfo_rename_function)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ test_helpers_module_entry
 */
zend_module_entry test_helpers_module_entry = {
	STANDARD_MODULE_HEADER,
	"test_helpers",
	test_helpers_functions,
	PHP_MINIT(test_helpers),
	NULL,
	PHP_RINIT(test_helpers),
	PHP_RSHUTDOWN(test_helpers),
	PHP_MINFO(test_helpers),
	TEST_HELPERS_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

static int test_helpers_zend_startup(zend_extension *extension) /* {{{ */
{
	return zend_startup_module(&test_helpers_module_entry);
}
/* }}} */

#ifndef ZEND_EXT_API
#define ZEND_EXT_API    ZEND_DLEXPORT
#endif
ZEND_EXTENSION();

zend_extension zend_extension_entry = {
	"test_helpers",
	TEST_HELPERS_VERSION,
	"Johannes Schlueter, Scott MacVicar, Sebastian Bergmann",
	"http://github.com/johannes/php-test-helpers",
	"Copyright (c) 2009-2013",
	test_helpers_zend_startup,
	NULL,           /* shutdown_func_t */
	NULL,           /* activate_func_t */
	NULL,           /* deactivate_func_t */
	NULL,           /* message_handler_func_t */
	NULL,           /* op_array_handler_func_t */
	NULL,           /* statement_handler_func_t */
	NULL,           /* fcall_begin_handler_func_t */
	NULL,           /* fcall_end_handler_func_t */
	NULL,           /* op_array_ctor_func_t */
	NULL,           /* op_array_dtor_func_t */
	STANDARD_ZEND_EXTENSION_PROPERTIES
};

#ifdef COMPILE_DL_TEST_HELPERS
ZEND_GET_MODULE(test_helpers)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
