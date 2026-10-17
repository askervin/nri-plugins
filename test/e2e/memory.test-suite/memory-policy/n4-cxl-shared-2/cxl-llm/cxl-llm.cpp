// cxl-llm: answer a prompt with a GGUF model that llama.cpp maps straight
// from a devdax device (shared CXL memory), from an inherited fd of one, or
// from a regular file; and write a model into a devdax device.
//
// The model on a devdax device is a GGUF file at offset 0, followed by zeros
// up to the device alignment (what --write leaves there). llama.cpp maps the
// device itself, so the weights stay in the device memory and every access
// reads them there. A regular file is mapped through the page cache of the
// node. Weight repacking is off: it would copy weights into process memory.
//
// Output: the answer on stdout, and on stderr the lines
//   cxl-llm: answer: TEXT                  (TEXT with \n for newlines)
//   cxl-llm: source=dax|file path=P model_bytes=N threads=N load_ms=T
//            prompt_tokens=N ttft_ms=T gen_tokens=N gen_tps=R total_ms=T
//            rss_kb=N rss_anon_kb=N rss_file_kb=N rss_shmem_kb=N  (one line;
//            model_bytes: the length that llama.cpp maps; rss_*: kB of
//            /proc/self/status)
//   cxl-llm: holding until FILE exists     (--hold FILE)
//   cxl-llm: done
// The writer prints "cxl-llm: wrote N bytes of SRC to DEV (mapping M bytes)
// in T ms", T the time of the copy.
// Exit status: 0 ok, 1 error, 2 usage.
//
// Builds with glibc only (see open_dax_model); build.sh links it statically.

#include "gguf.h"
#include "llama.h"

#include <algorithm>
#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const size_t DEFAULT_ALIGN = 2 << 20;

static const char * USAGE =
    "Usage:\n"
    "  cxl-llm (-m PATH | --fd N) [-t THREADS] [-n TOKENS] [--size BYTES] [--hold FILE] [-v] [PROMPT...]\n"
    "  cxl-llm --write SRC (-m DEV | --fd N) [--size BYTES]\n"
    "\n"
    "Answer PROMPT (default \"hello\") with the GGUF model in PATH: a devdax\n"
    "device (/dev/daxX.Y) or a regular file. Greedy decoding, the chat template\n"
    "of the model, an empty think block for models that think by default.\n"
    "\n"
    "  -m PATH       devdax device or GGUF file\n"
    "  --fd N        an inherited open fd of a devdax device or a GGUF file\n"
    "                (fd 3 of \"cxl-request ... --exec\")\n"
    "  -t THREADS    threads (default 2)\n"
    "  -n TOKENS     generate at most TOKENS tokens (default 32)\n"
    "  --size BYTES  size of the devdax device (default: its sysfs size), for\n"
    "                example $CXL_<KEY>_SIZE\n"
    "  --hold FILE   after answering, keep the model mapped until FILE exists\n"
    "  --write SRC   copy the GGUF file SRC to offset 0 of the devdax device,\n"
    "                zero the rest of its last alignment unit, and exit\n"
    "  -v            llama.cpp log\n";

struct options {
    std::string path;
    int         fd        = -1;
    int         threads   = 2;
    int         n_predict = 32;
    long long   size      = -1;
    std::string hold;
    std::string write_src;
    std::string prompt    = "hello";
    bool        verbose   = false;
};

static bool g_verbose = false;

// Prints a llama.cpp log line on stderr: errors always, the rest with -v.
static void log_cb(enum ggml_log_level level, const char * text, void *) {
    if (g_verbose || level == GGML_LOG_LEVEL_ERROR) {
        fputs(text, stderr);
    }
}

static int64_t g_start_us = 0;

// Returns milliseconds since t_us (ggml_time_us).
static double ms_since(int64_t t_us) {
    return (ggml_time_us() - t_us) / 1000.0;
}

// Returns true and sets v if s is a whole integer of at least min (decimal,
// or 0x hex).
static bool parse_int(const char * s, long long min, long long & v) {
    char * end = NULL;
    errno      = 0;
    v          = strtoll(s, &end, 0);
    return errno == 0 && end != s && *end == '\0' && v >= min;
}

// Parses the command line into o; returns -1 if it is valid, else the exit
// status (0 for --help).
static int parse_args(int argc, char ** argv, options & o) {
    int i = 1;
    for (; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            fputs(USAGE, stdout);
            return 0;
        }
        if (a == "-v") {
            o.verbose = true;
            continue;
        }
        if (a.size() < 2 || a[0] != '-') {
            break;
        }
        if (a != "-m" && a != "--fd" && a != "-t" && a != "-n" && a != "--size" && a != "--hold" && a != "--write") {
            fprintf(stderr, "cxl-llm: invalid option %s\n%s", a.c_str(), USAGE);
            return 2;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "cxl-llm: option %s needs a value\n%s", a.c_str(), USAGE);
            return 2;
        }
        const char * value = argv[++i];
        long long    n     = 0;
        if (a == "-m") {
            o.path = value;
        } else if (a == "--hold") {
            o.hold = value;
        } else if (a == "--write") {
            o.write_src = value;
        } else if (!parse_int(value, a == "--fd" ? 0 : 1, n) || (a != "--size" && n > 1 << 30)) {
            fprintf(stderr, "cxl-llm: invalid value \"%s\" of %s\n", value, a.c_str());
            return 2;
        } else if (a == "--fd") {
            o.fd = (int) n;
        } else if (a == "-t") {
            o.threads = (int) n;
        } else if (a == "-n") {
            o.n_predict = (int) n;
        } else {
            o.size = n;
        }
    }
    if (i < argc) {
        o.prompt = argv[i++];
        for (; i < argc; i++) {
            o.prompt += " ";
            o.prompt += argv[i];
        }
    }
    if (o.path.empty() == (o.fd < 0)) {
        fprintf(stderr, "cxl-llm: give either -m PATH or --fd N\n%s", USAGE);
        return 2;
    }
    return -1;
}

// Returns the integer sysfs attribute attr of the character device st, or
// -1 if it cannot be read.
static long long char_dev_attr(const struct stat & st, const char * attr) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/%s", major(st.st_rdev), minor(st.st_rdev), attr);
    FILE * f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    long long v = -1;
    if (fscanf(f, "%lli", &v) != 1) {
        v = -1;
    }
    fclose(f);
    return v;
}

// Returns n rounded up to a multiple of align (a power of two).
static size_t round_up(size_t n, size_t align) {
    return (n + align - 1) & ~(align - 1);
}

// Copies the file src to offset 0 of the devdax device fd of size bytes,
// zeroes the rest of the last alignment unit, and drops the page cache of
// src. Returns the exit status.
static int write_model(int fd, const std::string & dev, const std::string & src, size_t size, size_t align) {
    const int sfd = open(src.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat sst;
    if (sfd < 0 || fstat(sfd, &sst) != 0) {
        fprintf(stderr, "cxl-llm: %s: %s\n", src.c_str(), strerror(errno));
        return 1;
    }
    const size_t len = round_up((size_t) sst.st_size, align);
    if (len > size) {
        fprintf(stderr, "cxl-llm: %s (%lld bytes) does not fit %s (%zu bytes)\n", src.c_str(), (long long) sst.st_size,
                dev.c_str(), size);
        return 1;
    }
    char * dst = (char *) mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (dst == MAP_FAILED) {
        fprintf(stderr, "cxl-llm: mmap %s for writing (%zu bytes): %s\n", dev.c_str(), len, strerror(errno));
        return 1;
    }
    const int64_t t_copy = ggml_time_us();
    size_t        done   = 0;
    while (done < (size_t) sst.st_size) {
        const ssize_t n = read(sfd, dst + done, std::min<size_t>(sst.st_size - done, 64 << 20));
        if (n <= 0) {
            fprintf(stderr, "cxl-llm: read %s: %s\n", src.c_str(), n < 0 ? strerror(errno) : "unexpected end of file");
            return 1;
        }
        done += n;
    }
    memset(dst + done, 0, len - done);
    const double copy_ms = ms_since(t_copy);
    munmap(dst, len);
    posix_fadvise(sfd, 0, 0, POSIX_FADV_DONTNEED);
    close(sfd);
    fprintf(stderr, "cxl-llm: wrote %zu bytes of %s to %s (mapping %zu bytes) in %.1f ms\n", done, src.c_str(),
            dev.c_str(), len, copy_ms);
    return 0;
}

// A read-only FILE over memory: the model in the devdax mapping.
struct mem_cookie {
    const char * base;
    size_t       len;
    off64_t      pos;
};

// Reads up to n bytes at the position of the cookie FILE into buf; returns
// the bytes read, 0 at the end.
static ssize_t mem_read(void * c, char * buf, size_t n) {
    mem_cookie * m = (mem_cookie *) c;
    if (m->pos < 0 || (size_t) m->pos >= m->len) {
        return 0;
    }
    n = std::min(n, m->len - (size_t) m->pos);
    memcpy(buf, m->base + m->pos, n);
    m->pos += n;
    return (ssize_t) n;
}

// Moves the position of the cookie FILE and sets *off to it; returns 0, or
// -1 with EINVAL for a position before the start.
static int mem_seek(void * c, off64_t * off, int whence) {
    mem_cookie * m    = (mem_cookie *) c;
    const off64_t at  = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? m->pos : (off64_t) m->len;
    const off64_t pos = at + *off;
    if (pos < 0) {
        errno = EINVAL;
        return -1;
    }
    m->pos = pos;
    *off   = pos;
    return 0;
}

// Closes the cookie FILE: the mapping and the fd stay; returns 0.
static int mem_close(void *) {
    return 0;
}

// Returns a FILE for llama.cpp that reads the model of the devdax device fd
// of size bytes and whose fileno() is fd, so that llama.cpp maps the device
// itself; model_len is the length of the model rounded up to align. Returns
// NULL with a message on error.
static FILE * open_dax_model(int fd, const std::string & dev, size_t size, size_t align, size_t & model_len) {
    const size_t map_len = size & ~(align - 1);
    void *       base    = mmap(NULL, map_len, PROT_READ, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "cxl-llm: mmap %s (%zu bytes): %s\n", dev.c_str(), map_len, strerror(errno));
        return NULL;
    }
    gguf_init_params gparams = { /*.no_alloc =*/true, /*.ctx =*/NULL };
    gguf_context *   gctx    = gguf_init_from_buffer(base, map_len, gparams);
    if (!gctx) {
        fprintf(stderr, "cxl-llm: %s: no GGUF model at offset 0\n", dev.c_str());
        return NULL;
    }
    // The tensor data follows the header, so the model ends where the
    // tensor that ends last ends.
    size_t end = gguf_get_data_offset(gctx);
    for (int64_t t = 0; t < gguf_get_n_tensors(gctx); t++) {
        end = std::max(end, gguf_get_data_offset(gctx) + gguf_get_tensor_offset(gctx, t) + gguf_get_tensor_size(gctx, t));
    }
    gguf_free(gctx);
    model_len = round_up(end, align);
    if (model_len > map_len) {
        fprintf(stderr, "cxl-llm: %s: the model (%zu bytes) does not fit the device (%zu bytes)\n", dev.c_str(), end,
                map_len);
        return NULL;
    }
    cookie_io_functions_t io = { mem_read, NULL, mem_seek, mem_close };
    FILE *                fp = fopencookie(new mem_cookie{ (const char *) base, model_len, 0 }, "rb", io);
    if (!fp) {
        fprintf(stderr, "cxl-llm: fopencookie: %s\n", strerror(errno));
        return NULL;
    }
    // glibc only: _fileno is a field of glibc's struct _IO_FILE; fileno()
    // of a cookie FILE returns it, and fclose() calls only mem_close, so the
    // fd stays open. llama.cpp maps fileno() for the size that the FILE
    // reports, model_len, a multiple of the device alignment.
    fp->_fileno = fd;
    return fp;
}

// Returns TEXT with backslashes and newlines escaped, for one output line.
static std::string one_line(const std::string & text) {
    std::string out;
    for (char c : text) {
        if (c == '\n') {
            out += "\\n";
        } else if (c == '\\') {
            out += "\\\\";
        } else {
            out += c;
        }
    }
    return out;
}

// Reads VmRSS, RssAnon, RssFile and RssShmem of this process in kB.
static void rss_kb(long & vmrss, long & anon, long & file, long & shmem) {
    vmrss = anon = file = shmem = -1;
    FILE * f                    = fopen("/proc/self/status", "r");
    if (!f) {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "VmRSS: %ld", &vmrss);
        sscanf(line, "RssAnon: %ld", &anon);
        sscanf(line, "RssFile: %ld", &file);
        sscanf(line, "RssShmem: %ld", &shmem);
    }
    fclose(f);
}

// Prints that the model is held and waits until the file path exists.
static void hold(const std::string & path) {
    fprintf(stderr, "cxl-llm: holding until %s exists\n", path.c_str());
    while (access(path.c_str(), F_OK) != 0) {
        usleep(200 * 1000);
    }
}

// Answers the prompt with the model, prints the answer and the summary,
// and with --hold keeps the model until the hold file exists. Returns the
// exit status.
static int answer(llama_model * model, const options & o, const std::string & source, size_t model_len,
                  double load_ms) {
    const llama_vocab * vocab = llama_model_get_vocab(model);

    const char *        tmpl = llama_model_chat_template(model, NULL);
    llama_chat_message  msg  = { "user", o.prompt.c_str() };
    std::vector<char>   buf(4096 + o.prompt.size() * 2);
    const int           n    = llama_chat_apply_template(tmpl, &msg, 1, true, buf.data(), buf.size());
    if (n < 0 || (size_t) n > buf.size()) {
        fprintf(stderr, "cxl-llm: cannot apply the chat template of the model\n");
        return 1;
    }
    std::string text(buf.data(), n);
    if (tmpl && strstr(tmpl, "enable_thinking")) {
        // What the template of a thinking model (Qwen3) emits for
        // enable_thinking=false.
        text += "<think>\n\n</think>\n\n";
    }

    const int                n_prompt = -llama_tokenize(vocab, text.c_str(), text.size(), NULL, 0, true, true);
    std::vector<llama_token> tokens(n_prompt);
    if (llama_tokenize(vocab, text.c_str(), text.size(), tokens.data(), tokens.size(), true, true) < 0) {
        fprintf(stderr, "cxl-llm: cannot tokenize the prompt\n");
        return 1;
    }

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx                = n_prompt + o.n_predict;
    cparams.n_batch              = n_prompt;
    cparams.n_threads            = o.threads;
    cparams.n_threads_batch      = o.threads;
    llama_context * ctx          = llama_init_from_model(model, cparams);
    if (!ctx) {
        fprintf(stderr, "cxl-llm: cannot create the context\n");
        return 1;
    }
    llama_sampler * smpl = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(smpl, llama_sampler_init_greedy());

    llama_batch   batch   = llama_batch_get_one(tokens.data(), tokens.size());
    const int64_t t_gen   = ggml_time_us();
    int64_t       t_first = 0;
    int           n_gen   = 0;
    std::string   out;
    llama_token   tok;
    for (int n_pos = 0; n_pos + batch.n_tokens < n_prompt + o.n_predict;) {
        if (llama_decode(ctx, batch)) {
            fprintf(stderr, "cxl-llm: decode failed\n");
            return 1;
        }
        n_pos += batch.n_tokens;
        tok = llama_sampler_sample(smpl, ctx, -1);
        if (n_gen == 0) {
            t_first = ggml_time_us();
        }
        if (llama_vocab_is_eog(vocab, tok)) {
            break;
        }
        char piece[256];
        const int len = llama_token_to_piece(vocab, tok, piece, sizeof(piece), 0, false);
        if (len < 0) {
            fprintf(stderr, "cxl-llm: cannot convert a token\n");
            return 1;
        }
        out.append(piece, len);
        n_gen++;
        batch = llama_batch_get_one(&tok, 1);
    }
    const double ttft_ms = (t_first - t_gen) / 1000.0;
    const double gen_ms  = n_gen > 1 ? ms_since(t_first) : 0;
    printf("%s\n", out.c_str());
    fflush(stdout);

    long vmrss, anon, file, shmem;
    rss_kb(vmrss, anon, file, shmem);
    fprintf(stderr, "cxl-llm: answer: %s\n", one_line(out).c_str());
    fprintf(stderr,
            "cxl-llm: source=%s path=%s model_bytes=%zu threads=%d load_ms=%.1f prompt_tokens=%d ttft_ms=%.1f "
            "gen_tokens=%d gen_tps=%.2f total_ms=%.1f rss_kb=%ld rss_anon_kb=%ld rss_file_kb=%ld rss_shmem_kb=%ld\n",
            source.c_str(), o.fd >= 0 ? ("fd:" + std::to_string(o.fd)).c_str() : o.path.c_str(), model_len, o.threads,
            load_ms, n_prompt, ttft_ms, n_gen, n_gen > 1 ? (n_gen - 1) * 1000.0 / gen_ms : 0.0, ms_since(g_start_us),
            vmrss, anon, file, shmem);
    fflush(stderr);

    if (!o.hold.empty()) {
        hold(o.hold);
    }
    llama_sampler_free(smpl);
    llama_free(ctx);
    return 0;
}

int main(int argc, char ** argv) {
    std::setlocale(LC_NUMERIC, "C");
    g_start_us = ggml_time_us();

    options o;
    const int status = parse_args(argc, argv, o);
    if (status >= 0) {
        return status;
    }
    g_verbose = o.verbose;
    llama_log_set(log_cb, NULL);

    const std::string name = o.fd >= 0 ? "fd " + std::to_string(o.fd) : o.path;
    int               fd   = o.fd;
    if (fd < 0) {
        fd = open(o.path.c_str(), (o.write_src.empty() ? O_RDONLY : O_RDWR) | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "cxl-llm: open %s: %s\n", o.path.c_str(), strerror(errno));
            return 1;
        }
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "cxl-llm: fstat %s: %s\n", name.c_str(), strerror(errno));
        return 1;
    }
    const bool is_dax = S_ISCHR(st.st_mode);
    long long  size   = o.size;
    long long  align  = -1;
    if (is_dax) {
        if (size < 0) {
            size = char_dev_attr(st, "size");
        }
        align = char_dev_attr(st, "align");
    } else if (size < 0) {
        size = st.st_size;
    }
    if (align <= 0) {
        align = DEFAULT_ALIGN;
    }
    if (size <= 0) {
        fprintf(stderr, "cxl-llm: %s: unknown size, give --size\n", name.c_str());
        return 1;
    }

    if (!o.write_src.empty()) {
        return write_model(fd, name, o.write_src, size, align);
    }

    llama_model_params mparams = llama_model_default_params();
    mparams.n_gpu_layers       = 0;
    mparams.use_mmap           = true;
    mparams.use_direct_io      = false;
    mparams.use_extra_bufts    = false;

    size_t model_len = 0;
    FILE * fp        = NULL;
    if (is_dax) {
        fp = open_dax_model(fd, name, size, align, model_len);
    } else {
        model_len = size;
        fp        = fdopen(fd, "rb");
        if (!fp) {
            fprintf(stderr, "cxl-llm: fdopen %s: %s\n", name.c_str(), strerror(errno));
        }
    }
    if (!fp) {
        return 1;
    }

    const int64_t t_load = ggml_time_us();
    llama_model * model  = llama_model_load_from_file_ptr(fp, mparams);
    if (!model) {
        fprintf(stderr, "cxl-llm: cannot load the model from %s\n", name.c_str());
        return 1;
    }
    const int ret = answer(model, o, is_dax ? "dax" : "file", model_len, ms_since(t_load));
    llama_model_free(model);
    fprintf(stderr, "cxl-llm: done\n");
    return ret;
}
