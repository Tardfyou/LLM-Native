from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


VALIDATION_ENV_RELATIVE_PATH = Path(".patchweaver_env") / "validation_env.json"
MAKE_ENTER_DIR_RE = re.compile(r"make(?:\[\d+\])?: Entering directory ['`](?P<dir>[^'`]+)['`]")
MAKE_LEAVE_DIR_RE = re.compile(r"make(?:\[\d+\])?: Leaving directory ['`](?P<dir>[^'`]+)['`]")


@dataclass(frozen=True)
class GeneratedFile:
    kind: str
    dst: str
    content: str = ""
    src: str = ""


@dataclass(frozen=True)
class ProjectPreset:
    strategy: str
    source_dirs: Sequence[str]
    include_dirs: Sequence[str]
    forced_source_files: Sequence[str] = field(default_factory=tuple)
    define_flags: Sequence[str] = field(default_factory=tuple)
    extra_flags: Sequence[str] = field(default_factory=tuple)
    force_include_files: Sequence[str] = field(default_factory=tuple)
    configure_args: Sequence[str] = field(default_factory=tuple)
    exclude_globs: Sequence[str] = field(default_factory=tuple)
    generated_files: Sequence[GeneratedFile] = field(default_factory=tuple)


PROJECT_PRESETS: Dict[str, ProjectPreset] = {
    "libtiff": ProjectPreset(
        strategy="configure_make",
        source_dirs=("libtiff", "tools"),
        include_dirs=(".", "libtiff", "port"),
        define_flags=("-DHAVE_CONFIG_H", "-DJPEG_SUPPORT"),
        configure_args=(
            "--disable-shared",
            "--disable-cxx",
            "--disable-jpeg",
            "--disable-old-jpeg",
            "--disable-jbig",
            "--disable-lzma",
        ),
        generated_files=(
            GeneratedFile(
                kind="write",
                dst="port/jpeglib.h",
                content=textwrap.dedent(
                    """\
                    #ifndef PATCHWEAVER_STUB_JPEGLIB_H
                    #define PATCHWEAVER_STUB_JPEGLIB_H

                    #include <stddef.h>

                    #define JPEG_LIB_VERSION 80
                    #define BITS_IN_JSAMPLE 8
                    #define MAX_COMPONENTS 10
                    #define DCTSIZE 8
                    #define JPOOL_IMAGE 1
                    #define JPEG_EOI 0xD9
                    #define JPEG_HEADER_OK 1
                    #define JPEG_HEADER_TABLES_ONLY 2

                    typedef int boolean;
                    #ifndef TRUE
                    #define TRUE 1
                    #endif
                    #ifndef FALSE
                    #define FALSE 0
                    #endif

                    typedef unsigned char JSAMPLE;
                    typedef unsigned char JOCTET;
                    typedef unsigned int JDIMENSION;
                    typedef JSAMPLE *JSAMPROW;
                    typedef JSAMPROW *JSAMPARRAY;
                    typedef JSAMPARRAY *JSAMPIMAGE;

                    typedef enum {
                        JCS_UNKNOWN,
                        JCS_GRAYSCALE,
                        JCS_RGB,
                        JCS_YCbCr,
                        JCS_CMYK,
                        JCS_YCCK
                    } J_COLOR_SPACE;

                    struct jpeg_common_struct;
                    struct jpeg_compress_struct;
                    struct jpeg_decompress_struct;
                    struct jpeg_error_mgr;
                    struct jpeg_destination_mgr;
                    struct jpeg_source_mgr;
                    struct jpeg_component_info;
                    struct jpeg_memory_mgr;

                    typedef struct jpeg_common_struct *j_common_ptr;
                    typedef struct jpeg_compress_struct *j_compress_ptr;
                    typedef struct jpeg_decompress_struct *j_decompress_ptr;
                    typedef struct jpeg_error_mgr jpeg_error_mgr;
                    typedef struct jpeg_destination_mgr jpeg_destination_mgr;
                    typedef struct jpeg_source_mgr jpeg_source_mgr;
                    typedef struct jpeg_component_info jpeg_component_info;

                    typedef struct JQUANT_TBL {
                        boolean sent_table;
                    } JQUANT_TBL;

                    typedef struct JHUFF_TBL {
                        boolean sent_table;
                    } JHUFF_TBL;

                    struct jpeg_error_mgr {
                        void (*error_exit)(j_common_ptr cinfo);
                        void (*output_message)(j_common_ptr cinfo);
                        void (*format_message)(j_common_ptr cinfo, char *buffer);
                    };

                    struct jpeg_memory_mgr {
                        JSAMPARRAY (*alloc_sarray)(j_common_ptr cinfo, int pool_id,
                                                   JDIMENSION samplesperrow,
                                                   JDIMENSION numrows);
                        long max_memory_to_use;
                    };

                    struct jpeg_common_struct {
                        struct jpeg_error_mgr *err;
                        struct jpeg_memory_mgr *mem;
                        void *client_data;
                        boolean is_decompressor;
                    };

                    struct jpeg_destination_mgr {
                        JOCTET *next_output_byte;
                        size_t free_in_buffer;
                        void (*init_destination)(j_compress_ptr cinfo);
                        boolean (*empty_output_buffer)(j_compress_ptr cinfo);
                        void (*term_destination)(j_compress_ptr cinfo);
                    };

                    struct jpeg_source_mgr {
                        const JOCTET *next_input_byte;
                        size_t bytes_in_buffer;
                        void (*init_source)(j_decompress_ptr cinfo);
                        boolean (*fill_input_buffer)(j_decompress_ptr cinfo);
                        void (*skip_input_data)(j_decompress_ptr cinfo, long num_bytes);
                        boolean (*resync_to_restart)(j_decompress_ptr cinfo, int desired);
                        void (*term_source)(j_decompress_ptr cinfo);
                    };

                    struct jpeg_component_info {
                        int component_id;
                        int h_samp_factor;
                        int v_samp_factor;
                        int quant_tbl_no;
                        int dc_tbl_no;
                        int ac_tbl_no;
                        JDIMENSION width_in_blocks;
                        JDIMENSION downsampled_width;
                    };

                    struct jpeg_compress_struct {
                        struct jpeg_error_mgr *err;
                        struct jpeg_memory_mgr *mem;
                        void *client_data;
                        boolean is_decompressor;
                        jpeg_destination_mgr *dest;
                        JDIMENSION image_width;
                        JDIMENSION image_height;
                        int input_components;
                        J_COLOR_SPACE in_color_space;
                        int data_precision;
                        int bits_in_jsample;
                        jpeg_component_info *comp_info;
                        int num_components;
                        int max_v_samp_factor;
                        boolean raw_data_in;
                        boolean write_JFIF_header;
                        boolean write_Adobe_marker;
                        boolean optimize_coding;
                        JQUANT_TBL *quant_tbl_ptrs[4];
                        JHUFF_TBL *dc_huff_tbl_ptrs[4];
                        JHUFF_TBL *ac_huff_tbl_ptrs[4];
                    };

                    struct jpeg_decompress_struct {
                        struct jpeg_error_mgr *err;
                        struct jpeg_memory_mgr *mem;
                        void *client_data;
                        boolean is_decompressor;
                        jpeg_source_mgr *src;
                        JDIMENSION image_width;
                        JDIMENSION image_height;
                        JDIMENSION output_width;
                        JDIMENSION output_height;
                        JDIMENSION output_scanline;
                        J_COLOR_SPACE jpeg_color_space;
                        J_COLOR_SPACE out_color_space;
                        int data_precision;
                        int bits_in_jsample;
                        jpeg_component_info *comp_info;
                        int num_components;
                        int max_v_samp_factor;
                        boolean raw_data_out;
                        boolean do_fancy_upsampling;
                    };

                    static void patchweaver_jpeg_format_message(j_common_ptr cinfo, char *buffer)
                    {
                        (void)cinfo;
                        if (buffer) {
                            buffer[0] = '\\0';
                        }
                    }

                    static jpeg_error_mgr *jpeg_std_error(jpeg_error_mgr *err)
                    {
                        if (err) {
                            err->error_exit = 0;
                            err->output_message = 0;
                            err->format_message = patchweaver_jpeg_format_message;
                        }
                        return err;
                    }

                    static JSAMPARRAY patchweaver_jpeg_alloc_sarray(j_common_ptr cinfo, int pool_id,
                                                                    JDIMENSION samplesperrow,
                                                                    JDIMENSION numrows)
                    {
                        (void)cinfo;
                        (void)pool_id;
                        (void)samplesperrow;
                        (void)numrows;
                        return (JSAMPARRAY)0;
                    }

                    static void patchweaver_jpeg_init_common(struct jpeg_common_struct *cinfo,
                                                            boolean is_decompressor)
                    {
                        static struct jpeg_memory_mgr mem = { patchweaver_jpeg_alloc_sarray };
                        if (cinfo) {
                            cinfo->mem = &mem;
                            cinfo->is_decompressor = is_decompressor;
                        }
                    }

                    static void jpeg_create_compress(j_compress_ptr cinfo)
                    {
                        static jpeg_component_info comps[MAX_COMPONENTS];
                        patchweaver_jpeg_init_common((struct jpeg_common_struct *)cinfo, FALSE);
                        if (cinfo) {
                            cinfo->comp_info = comps;
                            cinfo->num_components = 3;
                            cinfo->max_v_samp_factor = 1;
                        }
                    }

                    static void jpeg_create_decompress(j_decompress_ptr cinfo)
                    {
                        static jpeg_component_info comps[MAX_COMPONENTS];
                        patchweaver_jpeg_init_common((struct jpeg_common_struct *)cinfo, TRUE);
                        if (cinfo) {
                            cinfo->comp_info = comps;
                            cinfo->num_components = 3;
                            cinfo->max_v_samp_factor = 1;
                        }
                    }

                    static void jpeg_set_defaults(j_compress_ptr cinfo) { (void)cinfo; }
                    static void jpeg_set_colorspace(j_compress_ptr cinfo, J_COLOR_SPACE colorspace)
                    {
                        if (cinfo) {
                            cinfo->in_color_space = colorspace;
                        }
                    }
                    static void jpeg_set_quality(j_compress_ptr cinfo, int quality, boolean force_baseline)
                    {
                        (void)cinfo;
                        (void)quality;
                        (void)force_baseline;
                    }
                    static void jpeg_suppress_tables(j_compress_ptr cinfo, boolean suppress)
                    {
                        (void)cinfo;
                        (void)suppress;
                    }
                    static void jpeg_start_compress(j_compress_ptr cinfo, boolean write_all_tables)
                    {
                        (void)cinfo;
                        (void)write_all_tables;
                    }
                    static JDIMENSION jpeg_write_scanlines(j_compress_ptr cinfo, JSAMPARRAY scanlines,
                                                           JDIMENSION num_lines)
                    {
                        (void)cinfo;
                        (void)scanlines;
                        return num_lines;
                    }
                    static JDIMENSION jpeg_write_raw_data(j_compress_ptr cinfo, JSAMPIMAGE data,
                                                          JDIMENSION num_lines)
                    {
                        (void)cinfo;
                        (void)data;
                        return num_lines;
                    }
                    static void jpeg_finish_compress(j_compress_ptr cinfo) { (void)cinfo; }
                    static void jpeg_write_tables(j_compress_ptr cinfo) { (void)cinfo; }
                    static int jpeg_read_header(j_decompress_ptr cinfo, boolean require_image)
                    {
                        (void)cinfo;
                        (void)require_image;
                        return JPEG_HEADER_OK;
                    }
                    static boolean jpeg_start_decompress(j_decompress_ptr cinfo)
                    {
                        (void)cinfo;
                        return TRUE;
                    }
                    static JDIMENSION jpeg_read_scanlines(j_decompress_ptr cinfo, JSAMPARRAY scanlines,
                                                          JDIMENSION max_lines)
                    {
                        (void)cinfo;
                        (void)scanlines;
                        return max_lines;
                    }
                    static JDIMENSION jpeg_read_raw_data(j_decompress_ptr cinfo, JSAMPIMAGE data,
                                                         JDIMENSION max_lines)
                    {
                        (void)cinfo;
                        (void)data;
                        return max_lines;
                    }
                    static boolean jpeg_finish_decompress(j_decompress_ptr cinfo)
                    {
                        (void)cinfo;
                        return TRUE;
                    }
                    static void jpeg_abort(j_common_ptr cinfo) { (void)cinfo; }
                    static void jpeg_destroy(j_common_ptr cinfo) { (void)cinfo; }
                    static boolean jpeg_resync_to_restart(j_decompress_ptr cinfo, int desired)
                    {
                        (void)cinfo;
                        (void)desired;
                        return TRUE;
                    }

                    #endif
                    """
                ),
            ),
            GeneratedFile(
                kind="write",
                dst="port/jerror.h",
                content=textwrap.dedent(
                    """\
                    #ifndef PATCHWEAVER_STUB_JERROR_H
                    #define PATCHWEAVER_STUB_JERROR_H

                    #define JMSG_LENGTH_MAX 200
                    #define JERR_OUT_OF_MEMORY 1
                    #define JWRN_JPEG_EOF 2
                    #define ERREXIT1(cinfo, code, p1) ((void)(cinfo), (void)(code), (void)(p1))
                    #define WARNMS(cinfo, code) ((void)(cinfo), (void)(code))

                    #endif
                    """
                ),
            ),
        ),
        exclude_globs=("tools/tiffinfoce.c",),
    ),
    "imagemagick": ProjectPreset(
        strategy="configure_make",
        source_dirs=("MagickCore", "coders"),
        include_dirs=(".", "MagickCore", "coders"),
        define_flags=("-DHAVE_CONFIG_H",),
        configure_args=(
            "--without-perl",
            "--without-x",
            "--disable-openmp",
            "--disable-shared",
        ),
    ),
    "graphicsmagick": ProjectPreset(
        strategy="configure_make",
        source_dirs=("magick", "coders"),
        include_dirs=(".", "magick", "coders", "png"),
        forced_source_files=("coders/png.c",),
        define_flags=("-DHAVE_CONFIG_H", "-DHasPNG", "-DJNG_SUPPORTED"),
        configure_args=(
            "--without-x",
            "--disable-shared",
        ),
    ),
    "binutils": ProjectPreset(
        strategy="configure_make",
        source_dirs=("bfd", "binutils", "libiberty"),
        include_dirs=(".", "bfd", "binutils", "include", "libiberty", "zlib", "intl"),
        forced_source_files=("binutils/readelf.c",),
        define_flags=("-DHAVE_CONFIG_H",),
        configure_args=(
            "--disable-nls",
            "--disable-werror",
            "--disable-gdb",
            "--disable-gdbserver",
            "--disable-sim",
        ),
    ),
    "elfutils": ProjectPreset(
        strategy="configure_make",
        source_dirs=("lib", "libelf", "libdw", "src/readelf.c"),
        include_dirs=(".", "lib", "libelf", "libdw", "libdwfl", "libdwelf", "libebl", "libasm", "backends", "src"),
        define_flags=("-DHAVE_CONFIG_H", "-D_GNU_SOURCE", "-DLOCALEDIR=\".\""),
        extra_flags=("-std=gnu99",),
        configure_args=(
            "--disable-nls",
            "--disable-debuginfod",
        ),
        exclude_globs=(
            "lib/dynamicsizehash.c",
            "src/addr2line.c",
            "src/arlib-argp.c",
            "src/elfcompress.c",
            "src/strip.c",
        ),
    ),
    "vim": ProjectPreset(
        strategy="configure_make",
        source_dirs=("src",),
        include_dirs=(".", "src", "src/auto", "src/proto"),
        define_flags=("-DHAVE_CONFIG_H",),
        configure_args=(
            "--with-features=small",
            "--disable-gui",
            "--without-x",
        ),
    ),
    "libming": ProjectPreset(
        strategy="manual",
        source_dirs=("src", "src/blocks", "util"),
        include_dirs=(".", "src", "src/blocks", "util", "ch/include"),
        force_include_files=("src/actiontypes.h",),
        exclude_globs=(
            "src/blocks/pngdbl.c",
            "src/blocks/gifdbl.c",
            "util/png2dbl.c",
            "util/dbl2png.c",
            "util/gif2mask.c",
            "util/gif2dbl.c",
            "util/outputscript.c",
            "util/old/*",
        ),
        generated_files=(
            GeneratedFile(
                kind="template_replace",
                src="src/ming.h.in",
                dst="src/ming.h",
                content=json.dumps(
                    {
                        "@MAJOR_VERSION@": "0",
                        "@MINOR_VERSION@": "4",
                        "@MICRO_VERSION@": "7",
                    },
                    ensure_ascii=True,
                ),
            ),
        ),
    ),
    "jhead": ProjectPreset(
        strategy="manual",
        source_dirs=(".",),
        include_dirs=(".",),
        exclude_globs=("myglob.c",),
    ),
    "jasper": ProjectPreset(
        strategy="manual",
        source_dirs=("src/libjasper/base", "src/libjasper/jpc", "src/libjasper/pnm", "src/libjasper/mif"),
        include_dirs=(".", "src/libjasper/include", "src/libjasper/base", "src/libjasper/jpc", "src/libjasper/pnm", "src/libjasper/mif"),
        extra_flags=("-std=gnu89", "-Wno-error=incompatible-function-pointer-types"),
        force_include_files=("src/libjasper/include/jasper/jas_debug.h",),
        generated_files=(
            GeneratedFile(
                kind="write",
                dst="src/libjasper/include/jasper/jas_config.h",
                content=textwrap.dedent(
                    """\
                    #ifndef JAS_CONFIG_H
                    #define JAS_CONFIG_H
                    #define JAS_CONFIGURE 1
                    #define longlong long long
                    #define ulonglong unsigned long long
                    #define HAVE_STDINT_H 1
                    #define HAVE_STDBOOL_H 1
                    #define HAVE_FCNTL_H 1
                    #define HAVE_LIMITS_H 1
                    #define HAVE_SYS_TYPES_H 1
                    #define HAVE_STDLIB_H 1
                    #define HAVE_STDDEF_H 1
                    #define HAVE_UNISTD_H 1
                    #endif
                    """
                ),
            ),
        ),
    ),
    "libzip": ProjectPreset(
        strategy="manual",
        source_dirs=("lib", "src"),
        include_dirs=(".", "lib", "lib/gladman-fcrypt", "src", "xcode"),
        define_flags=("-DHAVE_CONFIG_H", "-DHAVE_UNISTD_H"),
        exclude_globs=(
            "lib/*win32*",
            "lib/zip_source_winzip_aes_decode.c",
            "lib/zip_source_winzip_aes_encode.c",
            "lib/gladman-fcrypt/*",
            "lib/gladman-fcrypt.c",
            "lib/mkstemp.c",
            "lib/zip_random_win32.c",
            "lib/zip_source_win32a.c",
            "lib/zip_source_win32w.c",
            "lib/zip_source_win32handle.c",
            "lib/zip_source_win32utf8.c",
        ),
    ),
    "openjpeg": ProjectPreset(
        strategy="manual",
        source_dirs=("src/lib/openjp2", "src/bin/common", "src/bin/jp2"),
        include_dirs=(".", "src/lib/openjp2", "src/bin/common", "src/bin/jp2"),
        generated_files=(
            GeneratedFile(
                kind="write_if_missing",
                dst="src/lib/openjp2/opj_config.h",
                content=textwrap.dedent(
                    """\
                    #ifndef OPJ_CONFIG_H
                    #define OPJ_CONFIG_H
                    #define OPJ_HAVE_STDINT_H 1
                    #define OPJ_VERSION_MAJOR 2
                    #define OPJ_VERSION_MINOR 2
                    #define OPJ_VERSION_BUILD 0
                    #endif
                    """
                ),
            ),
            GeneratedFile(
                kind="write_if_missing",
                dst="src/lib/openjp2/opj_config_private.h",
                content=textwrap.dedent(
                    """\
                    #ifndef OPJ_CONFIG_PRIVATE_H
                    #define OPJ_CONFIG_PRIVATE_H
                    #define OPJ_HAVE_INTTYPES_H 1
                    #define OPJ_PACKAGE_VERSION "2.2.0"
                    #define OPJ_HAVE_FSEEKO 1
                    #endif
                    """
                ),
            ),
            GeneratedFile(
                kind="write_if_missing",
                dst="src/bin/common/opj_apps_config.h",
                content=textwrap.dedent(
                    """\
                    #ifndef OPJ_APPS_CONFIG_H
                    #define OPJ_APPS_CONFIG_H
                    #include "opj_config_private.h"
                    #endif
                    """
                ),
            ),
        ),
        exclude_globs=(
            "src/bin/jp3d/*",
            "src/bin/jpip/*",
            "src/bin/jp2/convertpng.c",
            "src/bin/jp2/converttif.c",
            "src/lib/openjp2/ppix_manager.c",
            "src/lib/openjp2/phix_manager.c",
            "src/lib/openjp2/thix_manager.c",
            "src/lib/openjp2/tpix_manager.c",
            "src/lib/openjp2/cidx_manager.c",
        ),
    ),
    "ngiflib": ProjectPreset(
        strategy="manual",
        source_dirs=(".",),
        include_dirs=(".",),
        exclude_globs=("SDLaffgif.c", "ngiflibSDL.c"),
    ),
    "xrdp": ProjectPreset(
        strategy="manual",
        source_dirs=("common", "xrdp/xrdp_login_wnd.c"),
        include_dirs=(".", "common", "libxrdp", "xrdp"),
        define_flags=("-DHAVE_CONFIG_H",),
        generated_files=(
            GeneratedFile(
                kind="write",
                dst="config_ac.h",
                content=textwrap.dedent(
                    """\
                    #ifndef CONFIG_AC_H
                    #define CONFIG_AC_H
                    #define HAVE_STDINT_H 1
                    #define HAVE_STDLIB_H 1
                    #define HAVE_STRING_H 1
                    #define HAVE_UNISTD_H 1
                    #define XRDP_SOCKET_PATH "/tmp/.xrdp"
                    #define XRDP_LOG_PATH "/tmp"
                    #define XRDP_CFG_PATH "/tmp"
                    #define XRDP_SHARE_PATH "/tmp"
                    #endif
                    """
                ),
            ),
        ),
        exclude_globs=(
            "common/ssl_calls.c",
            "common/pixman-region.c",
            "common/pixman-region16.c",
            "libxrdp/xrdp_orders.c",
            "libxrdp/xrdp_rdp.c",
            "libxrdp/xrdp_surface.c",
        ),
    ),
}


def validation_env_path(version_root: Path) -> Path:
    return version_root / VALIDATION_ENV_RELATIVE_PATH


def load_validation_env(target_path: str) -> Dict[str, Any]:
    start = Path(target_path).expanduser().resolve()
    candidates: List[Path] = []
    cursor = start if start.is_dir() else start.parent
    for current in [cursor, *cursor.parents]:
        candidates.append(current / VALIDATION_ENV_RELATIVE_PATH)
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload["env_path"] = str(candidate)
                return payload
        except Exception:
            continue
    return {}


def prepare_sample_environment(sample: Any) -> Dict[str, Any]:
    roots = {
        "vulnerable": Path(str(sample.vulnerable_path)).expanduser().resolve(),
        "fixed": Path(str(sample.fixed_path)).expanduser().resolve(),
    }
    result: Dict[str, Any] = {"sample_id": getattr(sample, "sample_id", ""), "versions": {}}
    for label, root in roots.items():
        result["versions"][label] = prepare_project_environment(
            project=str(getattr(sample, "project", "") or "").strip().lower(),
            version_root=root,
        )
    return result


def prepare_project_environment(project: str, version_root: Path) -> Dict[str, Any]:
    preset = PROJECT_PRESETS.get(project)
    version_root = version_root.expanduser().resolve()
    env_dir = validation_env_path(version_root).parent
    env_dir.mkdir(parents=True, exist_ok=True)
    if preset is None:
        manifest = _build_manual_manifest(project, version_root, None)
        _write_manifest(version_root, manifest)
        return manifest

    _materialize_generated_files(version_root, preset.generated_files)
    if preset.strategy == "configure_make":
        manifest = _prepare_configure_make(project, version_root, preset)
    else:
        manifest = _build_manual_manifest(project, version_root, preset)
    _write_manifest(version_root, manifest)
    return manifest


def _prepare_configure_make(project: str, version_root: Path, preset: ProjectPreset) -> Dict[str, Any]:
    env_dir = validation_env_path(version_root).parent
    _ensure_configure(project, version_root, preset, env_dir)
    compile_commands = _parse_make_dry_run(version_root, preset, env_dir)
    compile_commands = _merge_forced_source_commands(version_root, preset, compile_commands)
    if not compile_commands:
        return _build_manual_manifest(project, version_root, preset, notes=["configure_make_fallback_to_manual"])

    compile_db_path = env_dir / "compile_commands.json"
    compile_db_path.write_text(json.dumps(compile_commands, indent=2, ensure_ascii=False), encoding="utf-8")
    build_script_path = _write_codeql_build_script(env_dir, compile_commands)
    include_dirs = _dedupe(
        _manifest_include_dirs(version_root, preset.include_dirs)
        + _collect_include_dirs_from_compile_db(compile_commands)
    )
    define_flags = _dedupe(list(preset.define_flags) + _collect_define_flags_from_compile_db(compile_commands))
    return {
        "project": project,
        "version_root": str(version_root),
        "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "strategy": preset.strategy,
        "compile_commands_path": str(compile_db_path),
        "codeql_build_script": str(build_script_path),
        "include_dirs": include_dirs,
        "define_flags": define_flags,
        "extra_flags": list(preset.extra_flags),
        "force_include_files": _manifest_force_include_files(version_root, preset.force_include_files),
        "source_count": len(compile_commands),
        "notes": ["configure_make"],
    }


def _build_manual_manifest(
    project: str,
    version_root: Path,
    preset: Optional[ProjectPreset],
    notes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    env_dir = validation_env_path(version_root).parent
    preset = preset or ProjectPreset(strategy="manual", source_dirs=(".",), include_dirs=(".",))
    commands = _build_manual_compile_commands(version_root, preset)
    compile_db_path = env_dir / "compile_commands.json"
    compile_db_path.write_text(json.dumps(commands, indent=2, ensure_ascii=False), encoding="utf-8")
    build_script_path = _write_codeql_build_script(env_dir, commands)
    return {
        "project": project,
        "version_root": str(version_root),
        "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "strategy": "manual",
        "compile_commands_path": str(compile_db_path),
        "codeql_build_script": str(build_script_path),
        "include_dirs": _manifest_include_dirs(version_root, preset.include_dirs),
        "define_flags": list(preset.define_flags),
        "extra_flags": list(preset.extra_flags),
        "force_include_files": _manifest_force_include_files(version_root, preset.force_include_files),
        "source_count": len(commands),
        "notes": list(notes or []) + ["manual_compile_db"],
    }


def _ensure_configure(project: str, version_root: Path, preset: ProjectPreset, env_dir: Path) -> None:
    configure_path = version_root / "configure"
    if not configure_path.exists():
        return
    makefile_path = version_root / "Makefile"
    if makefile_path.exists():
        _ensure_recursive_makefiles(project, version_root, env_dir)
        return
    command = [str(configure_path), *preset.configure_args]
    log_path = env_dir / "configure.log"
    proc = subprocess.run(
        command,
        cwd=str(version_root),
        capture_output=True,
        text=True,
        check=False,
    )
    log_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"{project} configure failed: {proc.stderr or proc.stdout}")
    _ensure_recursive_makefiles(project, version_root, env_dir)


def _ensure_recursive_makefiles(project: str, version_root: Path, env_dir: Path) -> None:
    if project == "vim":
        _ensure_vim_generated_headers(version_root, env_dir)
        return
    if project != "binutils":
        return
    required_makefiles = (
        version_root / "bfd" / "Makefile",
        version_root / "binutils" / "Makefile",
        version_root / "libiberty" / "Makefile",
    )
    if all(path.exists() for path in required_makefiles):
        _ensure_binutils_generated_headers(version_root, env_dir)
        return
    command = ["make", "configure-host", "-k"]
    log_path = env_dir / "configure_host.log"
    proc = subprocess.run(
        command,
        cwd=str(version_root),
        capture_output=True,
        text=True,
        check=False,
    )
    log_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    if proc.returncode != 0 and not all(path.exists() for path in required_makefiles):
        raise RuntimeError(f"{project} configure-host failed: {proc.stderr or proc.stdout}")
    _ensure_binutils_generated_headers(version_root, env_dir)


def _ensure_binutils_generated_headers(version_root: Path, env_dir: Path) -> None:
    required_targets = (
        "bfd.h",
        "libbfd.h",
        "bfdver.h",
        "elf32-target.h",
        "elf64-target.h",
        "targmatch.h",
    )
    bfd_dir = version_root / "bfd"
    if all((bfd_dir / target).exists() for target in required_targets):
        return
    command = ["make", "-C", "bfd", *required_targets]
    log_path = env_dir / "generate_headers.log"
    proc = subprocess.run(
        command,
        cwd=str(version_root),
        capture_output=True,
        text=True,
        check=False,
    )
    log_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    if proc.returncode != 0 and not all((bfd_dir / target).exists() for target in required_targets):
        raise RuntimeError(f"binutils generated header step failed: {proc.stderr or proc.stdout}")


def _ensure_vim_generated_headers(version_root: Path, env_dir: Path) -> None:
    required_targets = (
        version_root / "src" / "auto" / "osdef.h",
        version_root / "src" / "auto" / "pathdef.c",
    )
    if all(path.exists() for path in required_targets):
        return
    command = ["make", "-C", "src", "auto/osdef.h", "auto/pathdef.c"]
    log_path = env_dir / "generate_vim_headers.log"
    proc = subprocess.run(
        command,
        cwd=str(version_root),
        capture_output=True,
        text=True,
        check=False,
    )
    log_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    if proc.returncode != 0 and not all(path.exists() for path in required_targets):
        raise RuntimeError(f"vim generated header step failed: {proc.stderr or proc.stdout}")


def _parse_make_dry_run(version_root: Path, preset: ProjectPreset, env_dir: Path) -> List[Dict[str, Any]]:
    proc = subprocess.run(
        ["make", "-n", "-k"],
        cwd=str(version_root),
        capture_output=True,
        text=True,
        check=False,
    )
    log_path = env_dir / "make_dry_run.log"
    log_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    combined = _join_continuations(proc.stdout or "")
    results: List[Dict[str, Any]] = []
    seen_files = set()
    current_dir = version_root
    for line in combined:
        enter_match = MAKE_ENTER_DIR_RE.search(line)
        if enter_match:
            current_dir = Path(enter_match.group("dir")).expanduser().resolve()
            continue
        leave_match = MAKE_LEAVE_DIR_RE.search(line)
        if leave_match:
            leaving_dir = Path(leave_match.group("dir")).expanduser().resolve()
            current_dir = leaving_dir.parent if leaving_dir != version_root else version_root
            continue
        for segment in _split_compile_candidates(line):
            entry = _compile_entry_from_make_line(segment, current_dir, version_root, preset)
            if not entry:
                continue
            key = str(Path(str(entry["file"])).resolve())
            if key in seen_files:
                continue
            seen_files.add(key)
            results.append(entry)
    return results


def _join_continuations(text: str) -> List[str]:
    lines = text.splitlines()
    merged: List[str] = []
    current = ""
    for line in lines:
        stripped = line.rstrip()
        if not stripped:
            if current:
                merged.append(current)
                current = ""
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        current += stripped
        merged.append(current)
        current = ""
    if current:
        merged.append(current)
    return merged


def _split_compile_candidates(line: str) -> List[str]:
    raw = str(line or "").strip()
    if not raw:
        return []
    segments = [raw]
    if ";" in raw:
        segments = [part.strip() for part in raw.split(";") if part.strip()]

    normalized: List[str] = []
    for segment in segments:
        token = _normalize_make_segment(segment)
        if not token:
            continue
        normalized.append(token)
    return normalized


def _normalize_make_segment(segment: str) -> str:
    token = str(segment or "").strip()
    if not token:
        return ""
    token = re.sub(
        r"`test -f '([^']+)' \|\| echo '\./'`([^\s]+)",
        r"\2",
        token,
    )
    token = re.sub(
        r'^\s*echo\s+".*?"\s+[^;]+\s*$',
        "",
        token,
    ).strip()
    return token


def _compile_entry_from_make_line(
    line: str,
    command_dir: Path,
    version_root: Path,
    preset: ProjectPreset,
) -> Optional[Dict[str, Any]]:
    raw = str(line or "").strip()
    if not raw:
        return None
    tokens = _safe_split(raw)
    if not tokens:
        return None
    source_token = _find_source_token(tokens)
    if not source_token:
        return None
    base_dir = command_dir.expanduser().resolve()
    source_path = (base_dir / source_token).resolve() if not Path(source_token).is_absolute() else Path(source_token).resolve()
    if not source_path.exists():
        return None
    if not _source_allowed(version_root, source_path, preset):
        return None

    compiler = "clang++" if source_path.suffix.lower() in {".cc", ".cpp", ".cxx"} else "clang"
    preset_include_args = [f"-I{include_dir}" for include_dir in _manifest_include_dirs(version_root, preset.include_dirs)]
    preset_force_include_args: List[str] = []
    for include_file in _manifest_force_include_files(version_root, preset.force_include_files):
        preset_force_include_args.extend(["-include", include_file])
    args = _dedupe(
        list(preset.define_flags)
        + list(preset.extra_flags)
        + preset_force_include_args
        + preset_include_args
        + _extract_relevant_args(tokens, base_dir)
    )
    obj_dir = version_root / ".patchweaver_env" / "objects"
    obj_dir.mkdir(parents=True, exist_ok=True)
    obj_path = obj_dir / (source_path.relative_to(version_root).as_posix().replace("/", "__") + ".o")
    command = [compiler, "-Qunused-arguments", "-c", str(source_path), "-o", str(obj_path), *args]
    return {
        "directory": str(base_dir),
        "file": str(source_path),
        "command": " ".join(shlex.quote(token) for token in command),
    }


def _build_manual_compile_commands(version_root: Path, preset: ProjectPreset) -> List[Dict[str, Any]]:
    commands: List[Dict[str, Any]] = []
    for source_path in _iter_source_files(version_root, preset):
        commands.append(_manual_compile_entry(version_root, preset, source_path))
    return commands


def _merge_forced_source_commands(
    version_root: Path,
    preset: ProjectPreset,
    compile_commands: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results = list(compile_commands)
    seen = {str(Path(str(entry.get("file", "") or "")).resolve()) for entry in results}
    for rel_path in preset.forced_source_files:
        source_path = (version_root / rel_path).resolve()
        if not source_path.exists() or source_path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            continue
        key = str(source_path)
        if key in seen:
            continue
        if not _source_allowed(version_root, source_path, preset):
            continue
        results.append(_manual_compile_entry(version_root, preset, source_path))
        seen.add(key)
    return results


def _manual_compile_entry(version_root: Path, preset: ProjectPreset, source_path: Path) -> Dict[str, Any]:
    obj_dir = version_root / ".patchweaver_env" / "objects"
    obj_dir.mkdir(parents=True, exist_ok=True)
    compiler = "clang++" if source_path.suffix.lower() in {".cc", ".cpp", ".cxx"} else "clang"
    obj_path = obj_dir / (source_path.relative_to(version_root).as_posix().replace("/", "__") + ".o")
    args = []
    for include_dir in _manifest_include_dirs(version_root, preset.include_dirs):
        args.append(f"-I{include_dir}")
    args.extend(preset.define_flags)
    args.extend(preset.extra_flags)
    for include_file in _manifest_force_include_files(version_root, preset.force_include_files):
        args.extend(["-include", include_file])
    command = [compiler, "-Qunused-arguments", "-c", str(source_path), "-o", str(obj_path), *args]
    return {
        "directory": str(version_root),
        "file": str(source_path),
        "command": " ".join(shlex.quote(token) for token in command),
    }


def _iter_source_files(version_root: Path, preset: ProjectPreset) -> Iterable[Path]:
    exts = {".c", ".cc", ".cpp", ".cxx"}
    seen = set()
    for rel_dir in preset.source_dirs:
        base = (version_root / rel_dir).resolve()
        if base.is_file() and base.suffix.lower() in exts:
            yield base
            continue
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in exts:
                continue
            if not _source_allowed(version_root, path, preset):
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            yield path.resolve()


def _source_allowed(version_root: Path, source_path: Path, preset: ProjectPreset) -> bool:
    rel = source_path.resolve().relative_to(version_root).as_posix()
    if rel.startswith(".patchweaver_env/"):
        return False
    if not _is_within_source_dirs(version_root, source_path.resolve(), preset.source_dirs):
        return False
    for pattern in preset.exclude_globs:
        if Path(rel).match(pattern):
            return False
    return True


def _is_within_source_dirs(version_root: Path, source_path: Path, source_dirs: Sequence[str]) -> bool:
    for rel_dir in source_dirs:
        root = (version_root / rel_dir).resolve()
        if root == version_root:
            return True
        try:
            source_path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _extract_relevant_args(tokens: Sequence[str], command_dir: Path) -> List[str]:
    result: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"-c", "-o", "-MF", "-MT", "-MQ"}:
            index += 2 if index + 1 < len(tokens) else 1
            continue
        if token in {"-I", "-D", "-U", "-include", "-isystem", "-iquote", "-imacros", "-x", "-std"}:
            if index + 1 < len(tokens):
                value = tokens[index + 1]
                resolved = _resolve_flag_value(token, value, command_dir)
                result.extend([token, resolved])
                index += 2
                continue
        if token.startswith("-I") and len(token) > 2:
            result.append("-I" + _resolve_include_path(token[2:], command_dir))
        elif token.startswith("-D") or token.startswith("-U"):
            result.append(token)
        elif token.startswith("-std="):
            result.append(token)
        elif token.startswith("-include"):
            value = token[len("-include") :]
            if value:
                result.extend(["-include", _resolve_include_path(value, command_dir)])
        elif token.startswith("-isystem"):
            value = token[len("-isystem") :]
            if value:
                result.extend(["-isystem", _resolve_include_path(value, command_dir)])
        elif token.startswith("-iquote"):
            value = token[len("-iquote") :]
            if value:
                result.extend(["-iquote", _resolve_include_path(value, command_dir)])
        elif token.startswith("-m") or token in {"-pthread", "-fPIC", "-fpic", "-fms-extensions", "-funsigned-char", "-fshort-wchar"}:
            result.append(token)
        index += 1
    return _dedupe(result)


def _resolve_flag_value(flag: str, value: str, version_root: Path) -> str:
    if flag in {"-I", "-include", "-isystem", "-iquote", "-imacros"}:
        return _resolve_include_path(value, version_root)
    return value


def _resolve_include_path(value: str, version_root: Path) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((version_root / path).resolve())


def _find_source_token(tokens: Sequence[str]) -> str:
    exts = (".c", ".cc", ".cpp", ".cxx")
    for token in reversed(tokens):
        lower = token.lower()
        if lower.endswith(exts):
            return token
    return ""


def _safe_split(command: str) -> List[str]:
    try:
        return shlex.split(command)
    except Exception:
        return command.split()


def _manifest_include_dirs(version_root: Path, include_dirs: Sequence[str]) -> List[str]:
    resolved: List[str] = []
    for item in include_dirs:
        candidate = (version_root / item).resolve()
        if candidate.exists():
            resolved.append(str(candidate))
    return _dedupe(resolved)


def _manifest_force_include_files(version_root: Path, include_files: Sequence[str]) -> List[str]:
    resolved: List[str] = []
    for item in include_files:
        candidate = (version_root / item).resolve()
        if candidate.exists() and candidate.is_file():
            resolved.append(str(candidate))
    return _dedupe(resolved)


def _collect_include_dirs_from_compile_db(entries: Sequence[Dict[str, Any]]) -> List[str]:
    collected: List[str] = []
    for entry in entries:
        for token in _safe_split(str(entry.get("command", "") or "")):
            if token.startswith("-I") and len(token) > 2:
                collected.append(token[2:])
    return _dedupe(collected)


def _collect_define_flags_from_compile_db(entries: Sequence[Dict[str, Any]]) -> List[str]:
    collected: List[str] = []
    for entry in entries:
        for token in _safe_split(str(entry.get("command", "") or "")):
            if token.startswith("-D"):
                collected.append(token)
    return _dedupe(collected)


def _materialize_generated_files(version_root: Path, generated_files: Sequence[GeneratedFile]) -> None:
    for item in generated_files:
        dst = (version_root / item.dst).resolve()
        dst.parent.mkdir(parents=True, exist_ok=True)
        if item.kind == "write":
            dst.write_text(item.content, encoding="utf-8")
            continue
        if item.kind == "write_if_missing":
            if dst.exists():
                continue
            dst.write_text(item.content, encoding="utf-8")
            continue
        if item.kind == "copy":
            src = (version_root / item.src).resolve()
            if src.exists():
                dst.write_text(src.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            continue
        if item.kind == "template_replace":
            src = (version_root / item.src).resolve()
            if not src.exists():
                continue
            try:
                replacements = json.loads(item.content or "{}")
            except Exception:
                replacements = {}
            rendered = src.read_text(encoding="utf-8", errors="ignore")
            if isinstance(replacements, dict):
                for key, value in replacements.items():
                    rendered = rendered.replace(str(key), str(value))
            dst.write_text(rendered, encoding="utf-8")


def _write_codeql_build_script(env_dir: Path, entries: Sequence[Dict[str, Any]]) -> Path:
    script_path = env_dir / "codeql_build.sh"
    lines = ["#!/bin/sh", "set -e"]
    for entry in entries:
        command = str(entry.get("command", "") or "").strip()
        if not command:
            continue
        lines.append(command)
    script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script_path.chmod(0o755)
    return script_path


def _write_manifest(version_root: Path, manifest: Dict[str, Any]) -> None:
    path = validation_env_path(version_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


def _dedupe(items: Sequence[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for item in items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        result.append(token)
    return result
