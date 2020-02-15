#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if FUSE_USE_VERSION < 30
#define FUSE_LOG_DEBUG 0
static void fuse_log(
	__attribute__((unused)) int level,
	__attribute__((unused)) char *format,
	...
) {
}
#endif

struct blob;
typedef struct blob *blob;
struct blob {
	char data[5];
	size_t size;
	blob next;
};

static struct options {
	const char *shadow;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--shadow=%s", shadow),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static ssize_t blob_fill_buffer(blob b, char *buf, size_t size, off_t offset) {
	int ret = 0;

	while (b != NULL && offset > (off_t)b->size) {
		offset -= b->size;
		b = b->next;
	}

	while (b != NULL && size > 0) {
		off_t amount;

		if (size > b->size - offset) {
			amount = b->size - offset;
		}
		else {
			amount = size;
		}
		memcpy(buf, b->data + offset, amount);
		buf += amount;
		size -= amount;
		ret += amount;
		b = b->next;
		offset = 0;
	}

	return ret;
}

static void blob_free(blob b) {
	while (b != NULL) {
		blob t = b;
		b = b->next;
		free(t);
	}
}

static int myexec(char *prog, char *args[], blob *pblob) {
	int fds_data[2];
	int fds_control[2];
	int ret = -EFAULT;
	blob h = NULL;
	blob t = NULL;
	pid_t child;

	*pblob = NULL;

	if ((h = t =  malloc(sizeof(*h))) == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}
	t->size = 0;
	t->next = NULL;

	if (pipe(fds_data) == -1) {
		ret = -errno;
		goto cleanup;
	}

	if (pipe(fds_control) == -1) {
		ret = -errno;
		goto cleanup;
	}

	if ((child = fork()) == -1) {
		ret = -errno;
		goto cleanup;
	}
	else if (child == 0) {
		struct rlimit r;
		int null;
		int myerrno;
		unsigned long i;

		close(fds_data[0]);
		close(fds_control[0]);

		if ((null = open("/dev/null", O_RDWR)) == -1) {
			goto child_cleanup;
		}

		if (dup2(null, 0) == -1) {
			goto child_cleanup;
		}
		if (dup2(fds_data[1], 1) == -1) {
			goto child_cleanup;
		}
		/* TODO: redirect the stderr to log file */
		if (dup2(null, 2) == -1) {
			goto child_cleanup;
		}
		if (dup2(fds_control[1], 3) == -1) {
			goto child_cleanup;
		}
		fds_control[1] = 3;

		if (getrlimit(RLIMIT_NOFILE, &r) == -1) {
			goto child_cleanup;
		}
		for (i = 4;i < r.rlim_cur;i++) {
			close(i);
		}
		
		if (execv(prog, args) == -1) {
			goto child_cleanup;
		}

	child_cleanup:

		myerrno = errno;
		{
			char *p = (char *)&myerrno;
			size_t s = sizeof(myerrno);
			while (s > 0) {
				ssize_t r;
				if ((r = write(fds_control[0], &myerrno, sizeof(myerrno))) == -1) {
					break;	/* we have nothing to do... */
				}
				s -= r;
				p += r;
			}
		}
		_exit(1);
	}
	else {
		ssize_t s;
		int error;
		int status;

		close(fds_data[1]);
		close(fds_control[1]);

		do {
			if ((t->next = malloc(sizeof(*t))) == NULL) {
				ret = -ENOMEM;
				goto cleanup;
			}
			t = t->next;
			t->next = NULL;
			t->size = 0;

			if ((s = read(fds_data[0], t->data, sizeof(t->data))) == -1) {
				ret = -errno;
				goto cleanup;
			}
			t->size = s;
		} while(s != 0);

		if (read(fds_control[0], &error, sizeof(error)) == sizeof(error)) {
			ret = -error;
			goto cleanup;
		}
		if (waitpid(child, &status, 0) == -1) {
			ret = -errno;
			goto cleanup;
		}
		if (!WIFEXITED(status)) {
			ret = -ECHILD;
			goto cleanup;
		}
		if (WEXITSTATUS(status) != 0) {
			ret = -EFAULT;
			goto cleanup;
		}
	}

	ret = 0;
	*pblob = h;
	h = NULL;

cleanup:

	blob_free(h);

	return ret;
}

#if FUSE_USE_VERSION >= 30
static void *fuse_exec_init(
	__attribute__((unused)) struct fuse_conn_info *conn,
	struct fuse_config *cfg
) {
	cfg->direct_io = 1;
	return NULL;
}
#endif

static int fuse_exec_getattr(
	const char *path, struct stat *stbuf
#if FUSE_USE_VERSION >= 30
	,
	__attribute__((unused)) struct fuse_file_info *fi
#endif
) {
	struct stat stat1;
	char name[PATH_MAX];
	int ret = -EFAULT;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	}
	else {
		snprintf(name, sizeof(name), "%s%s", options.shadow, path);
		name[sizeof(name)-1] = '\0';

		if (stat(name, &stat1) == -1) {
			ret = -errno;
			goto cleanup;
		}

		stbuf->st_mode = S_IFREG | 0444;;
		stbuf->st_nlink = 1;
	}

	ret = 0;

cleanup:

	return ret;
}

static int fuse_exec_readdir(
	const char *path,
	void *buf,
	fuse_fill_dir_t filler,
	__attribute__((unused)) off_t offset,
	__attribute__((unused)) struct fuse_file_info *fi
#if FUSE_USE_VERSION >= 30
	,
	__attribute__((unused)) enum fuse_readdir_flags flags
#endif
)
{
	DIR *d = NULL;
	struct dirent *entry;
	int ret = -EFAULT;

	if (strcmp(path, "/") != 0) {
		ret = -ENOENT;
		fuse_log(FUSE_LOG_DEBUG, "Path is not '/'\n");
		goto cleanup;
	}

	if ((d = opendir(options.shadow)) == NULL) {
		ret = -ENOENT;
		fuse_log(FUSE_LOG_DEBUG, "opendir '%s' failed\n", options.shadow);
		goto cleanup;
	}

	while ((entry = readdir(d)) != NULL) {
		fuse_log(FUSE_LOG_DEBUG, "filling '%s'\n", entry->d_name);
		filler(
			buf,
			entry->d_name,
			NULL,
			0
#if FUSE_USE_VERSION >= 30
			,
			0
#endif
		);
	}

	ret = 0;

cleanup:

	if (d != NULL) {
		closedir(d);
	}

	return ret;
}

static int fuse_exec_open(const char *path, struct fuse_file_info *fi)
{
	char file[PATH_MAX];
	blob b = NULL;
	int ret = -EFAULT;
	int r;

	snprintf(file, sizeof(file), "%s%s", options.shadow, path);
	file[sizeof(file)-1] = '\0';

	if ((fi->flags & O_ACCMODE) != O_RDONLY) {
		ret = -EACCES;
		fuse_log(FUSE_LOG_DEBUG, "open request is not read only\n");
		goto cleanup;
	}

	{
		char *args[] = {file, NULL};
		if ((r = myexec(file, args, &b)) != 0) {
			ret = r;
			fuse_log(FUSE_LOG_DEBUG, "Cannot execute '%s'\n", file);
			goto cleanup;
		}
	}

	fi->fh = (uint64_t)b;
	b = NULL;
	ret = 0;

cleanup:

	blob_free(b);

	return ret;
}

static int fuse_exec_read(
	__attribute__((unused)) const char *path,
	char *buf,
	size_t size,
	off_t offset,
	struct fuse_file_info *fi
) {
	return blob_fill_buffer((blob)fi->fh, buf, size, offset);
}


static int fuse_exec_release(
	__attribute__((unused)) const char *path,
	struct fuse_file_info *fi
) {
	blob_free((blob)fi->fh);
	fi->fh = 0l;
	return 0;
}

static const struct fuse_operations fuse_exec_oper = {
#if FUSE_USE_VERSION >= 30
	.init           = fuse_exec_init,
#endif
	.getattr	= fuse_exec_getattr,
	.readdir	= fuse_exec_readdir,
	.open		= fuse_exec_open,
	.read		= fuse_exec_read,
	.release	= fuse_exec_release,
};

static void show_help()
{
	printf(
		"\n"
		"Options for fuse-exec:\n"
		"    --shadow=<s>         Name of shadow directory\n"
		"\n"
	);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int ret = 1;

	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) {
		goto cleanup;
	}

	if (options.show_help) {
		char *help_argv[] = {argv[0], "--help"};
		int help_argc = sizeof(help_argv) / sizeof(*help_argv);
		struct fuse_args help_args = FUSE_ARGS_INIT(help_argc, help_argv);
		ret = fuse_main(help_args.argc, help_args.argv, &fuse_exec_oper, NULL);
		show_help(argv[0]);
		fuse_opt_free_args(&help_args);
		goto cleanup;
	}

	if (options.shadow == NULL) {
		printf("Please specify shadow directory\n");
		goto cleanup;
	}

	ret = fuse_main(args.argc, args.argv, &fuse_exec_oper, NULL);

cleanup:

	fuse_opt_free_args(&args);
	return ret;
}
