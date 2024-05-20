/*
 * Copyright (C) 2019, Alex Bennée <alex.bennee@linaro.org>
 *
 * How vectorised is this code?
 *
 * Attempt to measure the amount of vectorisation that has been done
 * on some code by counting classes of instruction.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// static GMutex lock;
static GRWLock arr_lock;
static GArray *cpus;
static GHashTable *insns;
static GHashTable *access_cnt;
static GHashTable *stack_to_addr_map;
qemu_plugin_u64 stack_index;
GArray *call_symbs;
GArray *alloc_symbs;

typedef struct {
    char symb[8];
} AsmInstr;

typedef struct {
    char *symb;
    size_t real_len;
} FuncSymbol;

typedef struct {
    const char *symb;
    uint32_t shift;
} StackCall;

typedef struct {
    uint64_t start;
    size_t len;
} Allocation;

typedef struct {
    GArray *calls; // Arr of StackCall s
    int real_len;
    uint64_t hash;
} StackTrace;

typedef struct {
    StackCall* from;
    const char * to_symb;
    bool is_call_alloc;
    bool should_track_ret;
} InsnMeta;

typedef struct {
    struct qemu_plugin_register *handle;
    GByteArray *value;
    const char *name;
} Register;

typedef struct CPU {
    /* Ptr array of Register */
    Register *rax;
    Register *rdi;
    StackTrace *st;
    Allocation cur_alloc;
} CPU;

char unknown_symbol[] = "_unknown_";

FuncSymbol default_alloc_symbs[] = {{"_Znwm@\0", 6}, {"_Znam@\0", 6}, {"malloc@\0", 7},
                                        {"calloc@\0", 7}, {"realloc@\0", 8}, {"my_alloc\0", 9}};

AsmInstr default_call_symbs[] = {{"call\0"}, {"bl\0"}, {"jal\0"}};


// static gint cmp_exec_count(gconstpointer a, gconstpointer b)
// {
//     InsnExecCount *ea = (InsnExecCount *) a;
//     InsnExecCount *eb = (InsnExecCount *) b;
//     uint64_t count_a = qemu_plugin_u64_sum(ea->count);
//     uint64_t count_b = qemu_plugin_u64_sum(eb->count);
//     return count_a > count_b ? -1 : 1;
// }

// static void free_record(gpointer data)
// {
//     InsnExecCount *rec = (InsnExecCount *) data;
//     qemu_plugin_scoreboard_free(rec->count.score);
//     g_free(rec->insn);
//     g_free(rec);
// }

// static void plugin_exit(qemu_plugin_id_t id, void *p)
// {
//     return;
//     g_autoptr(GString) report = g_string_new("Instruction Classes:\n");
//     int i;
//     uint64_t total_count;
//     GList *counts;
//     InsnClassExecCount *class = NULL;

//     for (i = 0; i < class_table_sz; i++) {
//         class = &class_table[i];
//         switch (class->what) {
//         case COUNT_CLASS:
//             total_count = qemu_plugin_u64_sum(class->count);
//             if (total_count || verbose) {
//                 g_string_append_printf(report,
//                                        "Class: %-24s\t(%" PRId64 " hits)\n",
//                                        class->class,
//                                        total_count);
//             }
//             break;
//         case COUNT_INDIVIDUAL:
//             g_string_append_printf(report, "Class: %-24s\tcounted individually\n",
//                                    class->class);
//             break;
//         case COUNT_NONE:
//             g_string_append_printf(report, "Class: %-24s\tnot counted\n",
//                                    class->class);
//             break;
//         default:
//             break;
//         }
//     }

//     counts = g_hash_table_get_values(insns);
//     if (counts && g_list_next(counts)) {
//         g_string_append_printf(report, "Individual Instructions:\n");
//         counts = g_list_sort(counts, cmp_exec_count);

//         for (i = 0; i < limit && g_list_next(counts);
//              i++, counts = g_list_next(counts)) {
//             InsnExecCount *rec = (InsnExecCount *) counts->data;
//             g_string_append_printf(report,
//                                    "Instr: %-24s\t(%" PRId64 " hits)"
//                                    "\t(op=0x%08x/%s)\n",
//                                    rec->insn,
//                                    qemu_plugin_u64_sum(rec->count),
//                                    rec->opcode,
//                                    rec->class ?
//                                    rec->class->class : "un-categorised");
//         }
//         g_list_free(counts);
//     }

//     g_hash_table_destroy(insns);
//     for (i = 0; i < ARRAY_SIZE(class_tables); i++) {
//         for (int j = 0; j < class_tables[i].table_sz; ++j) {
//             qemu_plugin_scoreboard_free(class_tables[i].table[j].count.score);
//         }
//     }


//     qemu_plugin_outs(report->str);
// }

static void plugin_init(void)
{
    call_symbs = g_array_sized_new(0, 1, sizeof(AsmInstr), 8);
    call_symbs = g_array_insert_vals(call_symbs, 0, default_call_symbs, 3);

    
    alloc_symbs = g_array_sized_new(0, 1, sizeof(FuncSymbol), 8);
    alloc_symbs = g_array_insert_vals(alloc_symbs, 0, default_alloc_symbs, 6);

    insns = g_hash_table_new(NULL, g_direct_equal);
    access_cnt = g_hash_table_new(NULL, g_direct_equal);
    stack_to_addr_map = g_hash_table_new(NULL, g_direct_equal);

    stack_index = qemu_plugin_scoreboard_u64(
        qemu_plugin_scoreboard_new(sizeof(uint64_t)));
}

static CPU *get_cpu(int vcpu_index)
{
    CPU *c;
    g_rw_lock_reader_lock(&arr_lock);
    c = &g_array_index(cpus, CPU, vcpu_index);
    g_rw_lock_reader_unlock(&arr_lock);

    return c;
}

static Register *init_vcpu_register(qemu_plugin_reg_descriptor *desc, char *reg_name)
{
    Register *reg;
    g_autofree gchar *lower = g_utf8_strdown(desc->name, -1);
    int r;

    if (strcmp(g_intern_string(lower), reg_name) != 0) {
        return NULL;
    }
    reg = g_new0(Register, 1);
    reg->handle = desc->handle;
    reg->name = g_intern_string(lower);
    reg->value = g_byte_array_new();

    /* read the initial value */
    r = qemu_plugin_read_register(reg->handle, reg->value);
    g_assert(r > 0);
    return reg;
}

static Register *register_init(int vcpu_index, char *reg_name)
{
    
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();

    for (int r = 0; r < reg_list->len; r++) {
        qemu_plugin_reg_descriptor *rd = &g_array_index(
            reg_list, qemu_plugin_reg_descriptor, r);
        
        Register *reg = init_vcpu_register(rd, reg_name);
        if (reg != NULL) {
            return reg;
        }
    }
    return NULL;
}

static StackTrace *stack_trace_init(void) {
    StackTrace *st = g_malloc0(sizeof(StackTrace));
    st->calls = g_array_sized_new(0, 1, sizeof(StackCall), 64); // max stack trace deep is 64
    return st;
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    CPU *c;

    g_rw_lock_writer_lock(&arr_lock);
    if (vcpu_index >= cpus->len) {
        g_array_set_size(cpus, vcpu_index + 1);
    }
    g_rw_lock_writer_unlock(&arr_lock);

    c = get_cpu(vcpu_index);
    c->st = stack_trace_init();
    c->rax = register_init(vcpu_index, "rax");
    c->rdi = register_init(vcpu_index, "rdi");
}

static void call_insn_exec(unsigned int cpu_index, void *udata)
{
    InsnMeta *meta = (InsnMeta *)udata;
    CPU *c;
    int r;

    if (meta->from != NULL) {
        qemu_plugin_u64_add(stack_index, cpu_index, 1);
        g_assert(meta->should_track_ret == false);
    }

    uint64_t ind = qemu_plugin_u64_get(stack_index, cpu_index);
    if (ind >= 64) {
        return;
    }
    
    c = get_cpu(cpu_index);
    if (meta->from != NULL && meta->from->symb != NULL) {
        c->st->calls = g_array_insert_vals(c->st->calls, ind, meta->from, 1);
    }
    if (meta->should_track_ret) {
        g_byte_array_set_size(c->rax->value, 0);
        r = qemu_plugin_read_register(c->rax->handle, c->rax->value);
        g_assert(r > 0);
        uint64_t addr = *(uint64_t *)c->rax->value->data;
        StackCall *calls = (StackCall *)c->st->calls->data;
        for (int i = 1; i <= ind + 1; ++i) {
            StackCall call = calls[i];
            if (call.symb != NULL) {
                // printf("%s %p | ", call.symb, (void *)(uint64_t)call.shift);
            }
        }
        // printf("%p | %ld\n", (void *)addr, c->cur_alloc.len);
    }
    if (meta->from == NULL || meta->from->symb == NULL) {
        return;
    }
    // printf("From %s func to %s func\n", (meta->from->symb != NULL) ? meta->from->symb : unknown_symbol,\
                                        (meta->to_symb != NULL) ? meta->to_symb: unknown_symbol);
    
    if (meta->is_call_alloc) {
        // printf("This instr leads to Mem alloc function\n");
        g_byte_array_set_size(c->rdi->value, 0);
        r = qemu_plugin_read_register(c->rdi->handle, c->rdi->value);
        g_assert(r > 0);
        uint64_t size = *(uint64_t *)c->rdi->value->data;
        c->cur_alloc.len = size; 
        // printf("Alloc size in RAX: %ld\n", size);
    }
}


// static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
// {
//     char *symbol = (char *)udata;
//     qemu_plugin_u64_add(qemu_plugin_scoreboard_u64(cnt->exec_count),
//                         cpu_index, 1);
// }

bool is_after_alloc_call_insn(struct qemu_plugin_insn *insn) {
    int *res = (int *) g_hash_table_lookup(insns, GUINT_TO_POINTER(qemu_plugin_insn_vaddr(insn)));
    if(res == NULL) {
        return false;
    }
    return true;
}

bool is_alloc_func_symbol(const char *symbol) {
    if (symbol == NULL) {
        return false;
    }
    FuncSymbol *data = (FuncSymbol *)alloc_symbs->data;
    for (int i = 0; i < alloc_symbs->len; ++i) {
        if (g_str_has_prefix(symbol, data[i].symb)) {
            return true;
        }
    }
    return false;
}

uint64_t get_argument_vaddr(char *insn_disas) {
    char *res = strtok(insn_disas, " ");   
    char *end; 
    res = strtok(NULL, " "); 
    return strtoull(res, &end, 16);
}

uint32_t get_shift_from_symb_start(const char *symb, uint64_t vaddr) {
    uint64_t l = 0x1;
    uint64_t r = vaddr;
    uint64_t result = vaddr;

    if (symb == NULL) {
        return 0;
    }
    while (r - l > 1) {
        uint64_t mid = (l + r) / 2;
        const char *mid_symb = qemu_plugin_vaddr_symbol(mid);

        if (mid_symb != NULL && strcmp(mid_symb, symb) == 0) {
            result = mid;
            r = mid;
        } else {
            l = mid;
        }
    }
    return (uint32_t) (vaddr - result);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        bool has_cb = false;
        char *insn_disas = qemu_plugin_insn_disas(insn);
        char copy_disas[256];
        strcpy(copy_disas, insn_disas);

        if (g_str_has_prefix(insn_disas, "ret")) {
            has_cb = true;
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                insn, QEMU_PLUGIN_INLINE_ADD_U64, stack_index, -1);
        } else {
            InsnMeta *meta = g_malloc0(sizeof(InsnMeta));
            StackCall *call = g_malloc0(sizeof(StackCall));
            if (is_after_alloc_call_insn(insn)) {
                meta->should_track_ret = true;
                has_cb = true;
            }

            AsmInstr *call_insns = (AsmInstr *)call_symbs->data;
            for (int i = 0; i < call_symbs->len; ++i) {
                if (g_str_has_prefix(insn_disas, call_insns[i].symb)) {
                    has_cb = true;
                    call->symb = qemu_plugin_insn_symbol(insn);
                    call->shift = get_shift_from_symb_start(call->symb, qemu_plugin_insn_vaddr(insn));
                    meta->from = call;
                    meta->to_symb = qemu_plugin_vaddr_symbol(get_argument_vaddr(insn_disas));
                    meta->is_call_alloc = is_alloc_func_symbol(meta->to_symb);
                    break;
                }
            }
            if (has_cb) {
                if (meta->is_call_alloc) {
                    uint64_t next_insn_vaddr = qemu_plugin_insn_vaddr(insn) + \
                                                qemu_plugin_insn_size(insn);
                    g_hash_table_insert(insns, GUINT_TO_POINTER(next_insn_vaddr),
                            GUINT_TO_POINTER(0x1));
                }
                qemu_plugin_register_vcpu_insn_exec_cb(
                                insn, call_insn_exec,
                                QEMU_PLUGIN_CB_R_REGS, (void *)meta);
            } else {
                g_free(meta);
            }
        }
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    // int i;
    // for (i = 0; i < ARRAY_SIZE(class_tables); i++) {
    //     for (int j = 0; j < class_tables[i].table_sz; ++j) {
    //         struct qemu_plugin_scoreboard *score =
    //             qemu_plugin_scoreboard_new(sizeof(uint64_t));
    //         class_tables[i].table[j].count = qemu_plugin_scoreboard_u64(score);
    //     }
    // }

    // /* Select a class table appropriate to the guest architecture */
    // for (i = 0; i < ARRAY_SIZE(class_tables); i++) {
    //     ClassSelector *entry = &class_tables[i];
    //     if (!entry->qemu_target ||
    //         strcmp(entry->qemu_target, info->target_name) == 0) {
    //         class_table = entry->table;
    //         class_table_sz = entry->table_sz;
    //         break;
    //     }
    // }

    // for (i = 0; i < argc; i++) {
    //     char *p = argv[i];
    //     g_auto(GStrv) tokens = g_strsplit(p, "=", -1);
    //     if (g_strcmp0(tokens[0], "inline") == 0) {
    //         if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
    //             fprintf(stderr, "boolean argument parsing failed: %s\n", p);
    //             return -1;
    //         }
    //     } else if (g_strcmp0(tokens[0], "verbose") == 0) {
    //         if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &verbose)) {
    //             fprintf(stderr, "boolean argument parsing failed: %s\n", p);
    //             return -1;
    //         }
    //     } else if (g_strcmp0(tokens[0], "count") == 0) {
    //         char *value = tokens[1];
    //         int j;
    //         CountType type = COUNT_INDIVIDUAL;
    //         if (*value == '!') {
    //             type = COUNT_NONE;
    //             value++;
    //         }
    //         for (j = 0; j < class_table_sz; j++) {
    //             if (strcmp(value, class_table[j].opt) == 0) {
    //                 class_table[j].what = type;
    //                 break;
    //             }
    //         }
    //     } else {
    //         fprintf(stderr, "option parsing failed: %s\n", p);
    //         return -1;
    //     }
    // }
    cpus = g_array_sized_new(true, true, sizeof(CPU),
                             info->system_emulation ? info->system.max_vcpus : 1);
    plugin_init();
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    //qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
