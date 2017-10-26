###############################################################################
#                              AUTOTOOLS SETUP
###############################################################################

AC_PREREQ([2.69])

AC_INIT([SAFEcrypto], m4_esyscmd([tr -d '\n' < version]), [n.smyth@qub.ac.uk])

# Version-info specifications.  Update the table below for ANY change of version number.
#
#  Use LDFLAGS to pass the interface version number to the library: -version-info c:r:a
#  i.e. current:revision:age
#
#  1. If the interface is unchanged, but the implementation has changed or been fixed,
#     then increment r.
#  2. Otherwise, increment c and zero r.
#       1. If the interface has grown (that is, the new library is compatible with old
#          code), increment a.
#       2. If the interface has changed in an incompatible way (that is, functions have
#          changed or been removed), then zero a.
#
# Release      libsafecrypto.la
#  0.0-1        1:0:0
AC_SUBST(libsc_la_version_info,   1:0:0)

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

# AC_CANONICAL_HOST is needed to access the 'host_os' variable    
AC_CANONICAL_HOST

# Enable support for Valgrind
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_CHECK

# Detect the distribution. This is used for the default configuration and
# for some distro-specific build options.
AC_MSG_CHECKING([host distribution])
AC_ARG_WITH(distro, AS_HELP_STRING([--with-distro=DISTRO], [Specify the Linux distribution to target: One of redhat, oracle, centos, fedora, suse, gentoo, debian, arch, slackware, paldo, openmandriva or pardus.]))
if type lsb_release >/dev/null 2>&1 && test "z$with_distro" = "z"; then
  with_distro=`lsb_release -is`
fi
if test "z$with_distro" = "z"; then
  AC_CHECK_FILE(/etc/redhat-release,with_distro="redhat")
  AC_CHECK_FILE(/etc/oracle-release,with_distro="oracle")
  AC_CHECK_FILE(/etc/centos-release,with_distro="centos")
  AC_CHECK_FILE(/etc/fedora-release,with_distro="fedora")
  AC_CHECK_FILE(/etc/SuSE-release,with_distro="suse")
  AC_CHECK_FILE(/etc/gentoo-release,with_distro="gentoo")
  AC_CHECK_FILE(/etc/debian_version,with_distro="debian")
  AC_CHECK_FILE(/etc/arch-release,with_distro="arch")
  AC_CHECK_FILE(/etc/slackware-version,with_distro="slackware")
  AC_CHECK_FILE(/etc/frugalware-release,with_distro="frugalware")
  AC_CHECK_FILE(/etc/mandrakelinux-release, with_distro="openmandriva")
  AC_CHECK_FILE(/etc/mandriva-release,with_distro="openmandriva")
  AC_CHECK_FILE(/etc/pardus-release,with_distro="pardus")
fi
with_distro=`echo ${with_distro} | tr '[[:upper:]]' '[[:lower:]]'`

if test "z$with_distro" = "z"; then
  with_distro="unknown"
fi

AC_MSG_RESULT([$with_distro])
AM_CONDITIONAL([HAVE_DEBIAN], [test x"$with_distro" = "xdebian" -o x"$with_distro" = "xubuntu" -o x"$with_distro" = "xlinuxmint" -o x"$with_distro" = "xraspbian"])
AM_CONDITIONAL([DISTRO_CENTOS], [test "x$with_distro" = "xcentos"])


AC_CONFIG_LINKS([build_tools/ntt_table_gen/roots_of_unity.c:src/utils/arith/roots_of_unity.c
                 build_tools/ntt_table_gen/roots_of_unity.h:src/utils/arith/roots_of_unity.h
                 build_tools/ntt_table_gen/limb.c:src/utils/arith/limb.c
                 build_tools/ntt_table_gen/limb.h:src/utils/arith/limb.h
                 build_tools/ntt_table_gen/limb_base.c:src/utils/arith/limb_base.c
                 build_tools/ntt_table_gen/limb_base.h:src/utils/arith/limb_base.h
                 build_tools/ntt_table_gen/sc_math.c:src/utils/arith/sc_math.c
                 build_tools/ntt_table_gen/sc_math.h:src/utils/arith/sc_math.h])


AM_INIT_AUTOMAKE([1.13.4 subdir-objects foreign -Wall -Werror -Wno-portability])
AM_SILENT_RULES([yes])

AM_PATH_PYTHON(,, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])


if test -z $CFLAGS; then
    CFLAGS='-O2 -fomit-frame-pointer -march=native'
fi
AC_PROG_CC([gcc])
AC_PROG_CC_C99
if test -z $CXXFLAGS; then
    CXXFLAGS='-O2'
fi
AC_PROG_CXX([g++])

# Set the default language to C
AC_LANG([C++])

# Configure the Automake linker
AM_PROG_AR
#AM_PROG_LIBTOOL

# Initialize libtool
LT_PREREQ([2.4])
LT_INIT([shared static])

AC_CONFIG_FILES([build_tools/ntt_table_gen/ntt_table_gen.sh], [chmod +x build_tools/ntt_table_gen/ntt_table_gen.sh])
AC_CONFIG_FILES([setup_version.sh], [chmod +x setup_version.sh])
AC_CONFIG_FILES([pre-commit], [chmod +x pre-commit])
AC_OUTPUT_COMMANDS([cp pre-commit .git/hooks/pre-commit])

AC_ARG_ENABLE(design_doc,
AS_HELP_STRING([--enable-design-doc],
               [enable design documentation PDF generation, default: no]),
[case "${enableval}" in
             yes) design_doc=true ;;
             no)  design_doc=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-design-doc]) ;;
esac],
[design_doc=false])

AM_CONDITIONAL(HAVE_DESIGN_DOC, test x"$design_doc" = x"true")


AC_ARG_ENABLE(code_style_rules,
AS_HELP_STRING([--enable-code-style-rules],
               [enable coding style rules in distributable package, default: no]),
[case "${enableval}" in
             yes) code_style_rules=true ;;
             no)  code_style_rules=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-code-style-rules]) ;;
esac],
[code_style_rules=false])

AM_CONDITIONAL(HAVE_CODE_STYLE_RULES, test x"$code_style_rules" = x"true")

AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -D_GNU_SOURCE"])


# Development build - allows experimental code to be included in the project
AC_ARG_ENABLE([dev],
    AC_HELP_STRING([--enable-dev], [Include experminetal source code in the build]),
    [enable_dev=$enableval],
    [enable_dev="no"])

AM_CONDITIONAL([WITH_STABLE], [test "x${enable_dev}" = "xno"])
if test "x${enable_dev}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_STABLE"])
fi

# Censored build - removes unpublished research material from the distribution
AC_ARG_ENABLE([censorship],
    AC_HELP_STRING([--enable-censorship], [Exclude research material from the build]),
    [enable_censorship=$enableval],
    [enable_censorship="yes"])

AM_CONDITIONAL([WITH_CENSORSHIP], [test "x${enable_censorship}" = "xyes"])
if test "x${enable_censorship}" = "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_CENSORSHIP"])
fi


# SIMD is optional
enable_x86_simd=no
enable_arm_neon=no
AC_ARG_ENABLE([simd],
    AC_HELP_STRING([--disable-simd], [Include SIMD extensions, default: yes]))
if test "x$with_12bit" = "xyes"; then
  enable_simd=no
fi
if test "x${enable_simd}" != "xno"; then
  require_simd=no
  if test "x${enable_simd}" = "xyes"; then
    require_simd=yes
  fi
  # Check if we're on a supported CPU
  AC_MSG_CHECKING([if we have SIMD optimisations for cpu type])
  case "$host_cpu" in
    x86_64 | amd64)
      AC_MSG_RESULT([yes (x86_64)])
      simd_arch=x86_64
      enable_x86_simd=yes
      ;;
    i*86 | x86 | ia32)
      AC_MSG_RESULT([yes (i386)])
      simd_arch=i386
      enable_x86_simd=yes
      ;;
    arm*)
      AC_MSG_RESULT([yes (arm)])
      simd_arch=arm
      enable_arm_neon=yes
      ;;
    aarch64*)
      AC_MSG_RESULT([yes (arm64)])
      simd_arch=aarch64
      ;;
    mips*)
      AC_MSG_RESULT([yes (mips)])
      simd_arch=mips
      ;;
    powerpc*)
      AC_MSG_RESULT([yes (powerpc)])
      simd_arch=powerpc
      ;;
    *)
      AC_MSG_RESULT([no ("$host_cpu")])
      enable_simd=no;
      if test "x${require_simd}" = "xyes"; then
        AC_MSG_ERROR([SIMD support not available for this CPU.])
      else
        AC_MSG_WARN([SIMD support not available for this CPU.  Performance will decrease.])
      fi
      ;;
  esac

  if test "x${enable_simd}" != "xno"; then
    AC_DEFINE([WITH_SIMD], [1], [Use accelerated SIMD routines.])
  fi
else
  RPM_CONFIG_ARGS="$RPM_CONFIG_ARGS --without-simd"
fi


AC_ARG_ENABLE([x86_simd], AC_HELP_STRING([--disable-x86-simd], [Enable x86/x86_64 SIMD instructions]))
AC_ARG_ENABLE([arm_neon], AC_HELP_STRING([--disable-arm-neon], [Enable ARM NEON instructions]))

AS_IF([test "x${enable_arm_neon}" != "xno"], [
  AX_CHECK_COMPILE_FLAG(-mfpu=neon, ax_cv_support_neon_ext=yes, [])
  if test x"$ax_cv_support_neon_ext" = x"yes"; then
    CFLAGS_NEON="-mfpu=neon -DARM_NEON"
    AC_MSG_NOTICE([HAVE_NEON C preprocessor definition is enabled])
    AC_SUBST([AM_CFLAGS], ["-mfpu=neon -DARM_NEON"])
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_NEON"])
  else
    AC_MSG_NOTICE([HAVE_NEON C preprocessor definition is NOT enabled])
  fi

  AC_SUBST(CFLAGS_NEON)
])

AS_IF([test "x${enable_x86_simd}" != "xno"], [
oldcflags="$CFLAGS"
AC_MSG_CHECKING(for MMX instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("mmx"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_mmx=yes
     AC_DEFINE([HAVE_MMINTRIN_H], [1], [mmx is available])
     AX_CHECK_COMPILE_FLAG([-mmmx], [CFLAGS_MMX="-mmmx"])],
    [AC_MSG_RESULT(no)
     have_mmx=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for SSE2 instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("sse2"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_msse2=yes
     AC_DEFINE([HAVE_EMMINTRIN_H], [1], [sse2 is available])
     AX_CHECK_COMPILE_FLAG([-msse2], [CFLAGS_SSE2="-msse2"])],
    [AC_MSG_RESULT(no)]
     have_msse2=no)
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for SSE3 instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("sse3"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_msse3=yes
     AC_DEFINE([HAVE_PMMINTRIN_H], [1], [sse3 is available])
     AX_CHECK_COMPILE_FLAG([-msse3], [CFLAGS_SSE3="-msse3"])],
    [AC_MSG_RESULT(no)
     have_msse3=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for SSSE3 instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("ssse3"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_mssse3=yes
     AC_DEFINE([HAVE_TMMINTRIN_H], [1], [ssse3 is available])
     AX_CHECK_COMPILE_FLAG([-mssse3], [CFLAGS_SSSE3="-mssse3"])],
    [AC_MSG_RESULT(no)
     have_mssse3=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for SSE4.1 instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("sse4.1"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_msse41=yes
     AC_DEFINE([HAVE_SMMINTRIN_H], [1], [sse4.1 is available])
     AX_CHECK_COMPILE_FLAG([-msse4.1], [CFLAGS_SSE41="-msse4.1"])],
    [AC_MSG_RESULT(no)
     have_msse41=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for SSE4.2 instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("sse4.2"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_msse42=yes
     AC_DEFINE([HAVE_SMMINTRIN_H], [1], [sse4.2 is available])
     AX_CHECK_COMPILE_FLAG([-msse4.2], [CFLAGS_SSE42="-msse4.2"])],
    [AC_MSG_RESULT(no)
     have_msse42=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
AC_MSG_CHECKING(for AVX instruction set)
AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("avx"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_avx=yes
     AC_DEFINE([HAVE_AVXINTRIN_H], [1], [AVX is available])
     AX_CHECK_COMPILE_FLAG([-mavx], [CFLAGS_AVX="-mavx"])],
    [AC_MSG_RESULT(no)
     have_avx=no])
CFLAGS="$oldcflags"

oldcflags="$CFLAGS"
  AC_MSG_CHECKING(for AVX2 instruction set)
  AC_RUN_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
]], [[
  __builtin_cpu_init ();
  if (__builtin_cpu_supports("avx2"))
    return 0;
  return 1;
]])],
    [AC_MSG_RESULT(yes)
     have_avx2=yes
     AC_DEFINE([HAVE_AVX2INTRIN_H], [1], [AVX2 is available])
     AX_CHECK_COMPILE_FLAG([-mavx2], [CFLAGS_AVX2="-mavx2"])],
    [AC_MSG_RESULT(no)
     have_avx2=no])
CFLAGS="$oldcflags"


dnl Add ALL available SIMD instruction set flags
if test x$have_mmx = xyes; then
  AC_MSG_NOTICE([HAVE_MMX C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -mmmx"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MMX"])
else
  AC_MSG_NOTICE([HAVE_MMX C preprocessor definition is NOT enabled])
fi
if test x$have_msse2 = xyes; then
  AC_MSG_NOTICE([HAVE_MSSE2 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -msse2"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MSSE2"])
else
  AC_MSG_NOTICE([HAVE_MSSE2 C preprocessor definition is NOT enabled])
fi
if test x$have_msse3 = xyes; then
  AC_MSG_NOTICE([HAVE_MSSE3 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -msse3"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MSSE3"])
else
  AC_MSG_NOTICE([HAVE_MSSE3 C preprocessor definition is NOT enabled])
fi
if test x$have_mssse3 = xyes; then
  AC_MSG_NOTICE([HAVE_MSSSE3 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -mssse3"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MSSSE3"])
else
  AC_MSG_NOTICE([HAVE_MSSSE3 C preprocessor definition is NOT enabled])
fi
if test x$have_msse41 = xyes; then
  AC_MSG_NOTICE([HAVE_MSSE41 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -msse4.1"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MSSE41"])
else
  AC_MSG_NOTICE([HAVE_MSSE41 C preprocessor definition is NOT enabled])
fi
if test x$have_msse42 = xyes; then
  AC_MSG_NOTICE([HAVE_MSSE42 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -msse4.2"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MSSE42"])
else
  AC_MSG_NOTICE([HAVE_MSSE42 C preprocessor definition is NOT enabled])
fi
if test x$have_avx = xyes; then
  AC_MSG_NOTICE([HAVE_AVX C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -mavx"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_AVX"])
else
  AC_MSG_NOTICE([HAVE_AVX C preprocessor definition is NOT enabled])
fi
if test x$have_avx2 = xyes; then
  AC_MSG_NOTICE([HAVE_AVX2 C preprocessor definition is enabled])
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -mavx2"])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_AVX2"])
else
  AC_MSG_NOTICE([HAVE_AVX2 C preprocessor definition is NOT enabled])
fi

AC_SUBST(CFLAGS_MMX)
AC_SUBST(CFLAGS_SSE2)
AC_SUBST(CFLAGS_SSE3)
AC_SUBST(CFLAGS_SSSE3)
AC_SUBST(CFLAGS_SSE41)
AC_SUBST(CFLAGS_AVX)
AC_SUBST(CFLAGS_AVX2)
])

AM_CONDITIONAL([WITH_SIMD], [test "x$enable_simd" != "xno"])
AM_CONDITIONAL([SIMD_I386], [test "x$simd_arch" = "xi386"])
AM_CONDITIONAL([SIMD_X86_64], [test "x$simd_arch" = "xx86_64"])
AM_CONDITIONAL([WITH_AVX2], [test "x$have_avx2" = "xyes"])
AM_CONDITIONAL([SIMD_ARM], [test "x$simd_arch" = "xarm"])
AM_CONDITIONAL([SIMD_ARM_64], [test "x$simd_arch" = "xaarch64"])
AM_CONDITIONAL([SIMD_MIPS], [test "x$simd_arch" = "xmips"])
AM_CONDITIONAL([SIMD_POWERPC], [test "x$simd_arch" = "xpowerpc"])


###############################################################################
#                             GNU GMP and MPFR
###############################################################################

# Check for the presence of libgmp
gnugmp_present=no
AC_CHECK_LIB(gmp, __gmpz_init,
  [gnugmp_present=yes],
  [AC_MSG_WARN([GNU MP not found, disabling all applicable features!])])
AM_CONDITIONAL([HAVE_GNUGMP], test "x${gnugmp_present}" != "xno")

# Check for the presence of libmpfr
gnumpfr_present=no
AC_CHECK_LIB(mpfr, mpfr_init2,
  [gnumpfr_present=yes],
  [AC_MSG_WARN([GNU MPFR not found, disabling all applicable features!])])
AM_CONDITIONAL([HAVE_GNUMPFR], test "x${gnumpfr_present}" != "xno")

AC_ARG_ENABLE([gmp],
    AC_HELP_STRING([--enable-gmp], [Enable support for multiple-precision arithmetic using GNU GMP (default: [yes - IF INSTALLED])]),
    [enable_gmp=$enableval],
    [enable_gmp=$gnugmp_present])

AC_ARG_ENABLE([mpfr],
    AC_HELP_STRING([--enable-mpfr], [Enable support for GNU MPFR (default: [yes - IF INSTALLED])]),
    [enable_mpfr=$enableval],
    [enable_mpfr=$gnumpfr_present])

if test "x${enable_mpfr}" = "xyes"; then
    if test "x${enable_gmp}" != "xyes"; then
        AC_MSG_ERROR([GNU MPFR cannot be used without GNU GMP.])
    fi
fi

AM_CONDITIONAL([WITH_GMP], [test "x${enable_gmp}" = "xyes"])
AM_CONDITIONAL([WITH_MPFR], [test "x${enable_mpfr}" = "xyes"])
if test "x${enable_gmp}" = "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DUSE_GMP_MULTIPLE_PRECISION"])
else
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DUSE_SAFECRYPTO_INTEGER_MP"])
fi
if test "x${enable_mpfr}" = "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DUSE_MPFR_MULTIPLE_PRECISION"])
else
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DUSE_SAFECRYPTO_FLOAT_MP"])
fi


###############################################################################
#                            MULTITHREADING SUPPORT
###############################################################################

AC_ARG_ENABLE([multithreading],
    AC_HELP_STRING([--enable-multithreading], [Enable support for multi-threading (default: yes)]),
    [enable_multithreading=$enableval],
    [enable_multithreading="yes"])

AM_CONDITIONAL([WITH_MULTITHREADING], [test "x${enable_multithreading}" = "xyes"])
if test "x${enable_multithreading}" = "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_MULTITHREADING"])
fi


###############################################################################
#                              BARE-METAL SUPPORT
###############################################################################

AC_ARG_ENABLE([baremetal],
    AC_HELP_STRING([--enable-baremetal], [Enable support for bare-metal (default: no)]),
    [enable_baremetal=$enableval],
    [enable_baremetal="no"])

AM_CONDITIONAL([WITH_BAREMETAL], [test "x${enable_baremetal}" = "xyes"])
if test "x${enable_baremetal}" = "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DENABLE_BAREMETAL"])
fi


###############################################################################
#                      RUNTIME OR STATIC NTT TABLE SUPPORT
###############################################################################

# Use of hardcoded NTT lookup tables or dynamically created
AC_MSG_CHECKING([for runtime Number Theoretic Transform (NTT) table creation])
AC_ARG_ENABLE([runtime-ntt], AC_HELP_STRING([--enable-runtime-ntt], [Enable support for runtime NTT tables]),
    [runtime_ntt=$enableval],
    [runtime_ntt="no"])
AC_MSG_RESULT([$runtime_ntt])
AM_CONDITIONAL([USE_RUNTIME_NTT_TABLES], [test x$runtime_ntt = xyes])
if test x$runtime_ntt = xyes; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DUSE_RUNTIME_NTT_TABLES"])
fi


###############################################################################
#                          CONSTRAINED SYSTEM SUPPORT
###############################################################################

constrained_system=no

AC_MSG_CHECKING([for constrained RAM])
AC_ARG_ENABLE([constrained-ram], AC_HELP_STRING([--enable-constrained-ram], [Enable support for constrained RAM usage]),
    [enable_constrained_ram=$enableval],
    [enable_constrained_ram="no"])
AC_MSG_RESULT([$enable_constrained_ram])
AM_CONDITIONAL([ENABLE_CONSTRAINED_RAM], [test "x$enable_constrained_ram" != "xno"])
if test x$enable_constrained_ram = xyes; then
    constrained_system=yes
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DCONSTRAINED_RAM"])
fi

AC_MSG_CHECKING([for constrained ROM])
AC_ARG_ENABLE([constrained-rom], AC_HELP_STRING([--enable-constrained-rom], [Enable support for constrained ROM usage]),
    [enable_constrained_rom=$enableval],
    [enable_constrained_rom="no"])
AC_MSG_RESULT([$enable_constrained_rom])
AM_CONDITIONAL([ENABLE_CONSTRAINED_ROM], [test "x$enable_constrained_rom" != "xno"])
if test x$enable_constrained_rom = xyes; then
    constrained_system=yes
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DCONSTRAINED_ROM"])
fi

AC_MSG_CHECKING([for constrained CPU])
AC_ARG_ENABLE([constrained-cpu], AC_HELP_STRING([--enable-constrained-cpu], [Enable support for constrained CPU usage]),
    [enable_constrained_cpu=$enableval],
    [enable_constrained_cpu="no"])
AC_MSG_RESULT([$enable_constrained_cpu])
AM_CONDITIONAL([ENABLE_CONSTRAINED_CPU], [test "x$enable_constrained_cpu" != "xno"])
if test x$enable_constrained_cpu = xyes; then
    constrained_system=yes
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DCONSTRAINED_CPU"])
fi

AM_CONDITIONAL([CONSTRAINED_SYSTEM], [test x$constrained_system = xyes])


###############################################################################
#                               SCHEME SUPPORT
###############################################################################

AC_MSG_CHECKING([for Public-Key Encryption support])
AC_ARG_ENABLE([encryption], AC_HELP_STRING([--enable-encryption], [Enable support for Public-Key Encryption]),
    [enable_encryption=$enableval],
    [enable_encryption="yes"])
AC_MSG_RESULT([$enable_encryption])
AM_CONDITIONAL([ENABLE_ENCRYPTION], [test "x$enable_encryption" != "xno"])
if test x$enable_encryption = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_ENCRYPTION"])
fi

AC_MSG_CHECKING([for Digital Signatures Schemes support])
AC_ARG_ENABLE([signatures], AC_HELP_STRING([--enable-signatures], [Enable support for Digital Signature Schemes]),
    [enable_signatures=$enableval],
    [enable_signatures="yes"])
AC_MSG_RESULT([$enable_signatures])
AM_CONDITIONAL([ENABLE_SIGNATURES], [test "x$enable_signatures" != "xno"])
if test x$enable_signatures = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIGNATURES"])
fi

AC_MSG_CHECKING([for Key Encapsulation Mechanism support])
AC_ARG_ENABLE([kem],
    AC_HELP_STRING([--enable-kem], [Enable support for Key Encapsulation Mechanisms]),
    [enable_kem=$enableval],
    [enable_kem="yes"])
AC_MSG_RESULT([$enable_kem])
AM_CONDITIONAL([ENABLE_KEM], [test "x$enable_kem" != "xno"])
if test x$enable_kem = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_KEM"])
fi

AC_MSG_CHECKING([for Identity-Based Encryption support])
AC_ARG_ENABLE([ibe], AC_HELP_STRING([--enable-ibe], [Enable support for Identity-Based Encryption]),
    [enable_ibe=$enableval],
    [enable_ibe="yes"])
AC_MSG_RESULT([$enable_ibe])
AM_CONDITIONAL([ENABLE_IBE], [test "x$enable_ibe" != "xno"])
if test x$enable_ibe = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_IBE"])
fi

AC_MSG_CHECKING([for Digital Signatures Schemes support for clients])
AC_ARG_ENABLE([signatures-client], AC_HELP_STRING([--enable-signatures-client], [Enable support for Digital Signature Schemes for clients]),
    [enable_signatures_client=$enableval],
    [enable_signatures_client="yes"])
AC_MSG_RESULT([$enable_signatures_client])
AM_CONDITIONAL([ENABLE_SIGNATURES_CLIENT], [test "x$enable_signatures_client" != "xno"])
if test x$enable_signatures_client = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIGNATURES_CLIENT"])
fi

AC_MSG_CHECKING([for Digital Signatures Schemes support for servers])
AC_ARG_ENABLE([signatures-server], AC_HELP_STRING([--enable-signatures-server], [Enable support for Digital Signature Schemes for servers]),
    [enable_signatures_server=$enableval],
    [enable_signatures_server="yes"])
AC_MSG_RESULT([$enable_signatures_server])
AM_CONDITIONAL([ENABLE_SIGNATURES_SERVER], [test "x$enable_signatures_server" != "xno"])
if test x$enable_signatures_server = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIGNATURES_SERVER"])
fi

AC_MSG_CHECKING([for Key Encapsulation Mechanism support for clients])
AC_ARG_ENABLE([kem-client], AC_HELP_STRING([--enable-kem-client], [Enable support for Key Encapsulation Mechanism for clients]),
    [enable_kem_client=$enableval],
    [enable_kem_client="yes"])
AC_MSG_RESULT([$enable_kem_client])
AM_CONDITIONAL([ENABLE_KEM_CLIENT], [test "x$enable_kem_client" != "xno"])
if test x$enable_kem_client = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_KEM_CLIENT"])
fi

AC_MSG_CHECKING([for Key Encapsulation Mechanism support for servers])
AC_ARG_ENABLE([kem-server], AC_HELP_STRING([--enable-kem-server], [Enable support for Key Encapsulation Mechanism for servers]),
    [enable_kem_server=$enableval],
    [enable_kem_server="yes"])
AC_MSG_RESULT([$enable_kem_server])
AM_CONDITIONAL([ENABLE_KEM_SERVER], [test "x$enable_kem_server" != "xno"])
if test x$enable_kem_server = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_KEM_SERVER"])
fi

AC_MSG_CHECKING([for Identity-Based Encryption support for clients])
AC_ARG_ENABLE([ibe-client], AC_HELP_STRING([--enable-ibe-client], [Enable support for Identity-Based Encryption for clients]),
    [enable_ibe_client=$enableval],
    [enable_ibe_client="yes"])
AC_MSG_RESULT([$enable_ibe_client])
AM_CONDITIONAL([ENABLE_IBE_CLIENT], [test "x$enable_ibe_client" != "xno"])
if test x$enable_ibe_client = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_IBE_CLIENT"])
fi

AC_MSG_CHECKING([for Identity-Based Encryption support for servers])
AC_ARG_ENABLE([ibe-server], AC_HELP_STRING([--enable-ibe-server], [Enable support for Identity-Based Encryption for servers]),
    [enable_ibe_server=$enableval],
    [enable_ibe_server="yes"])
AC_MSG_RESULT([$enable_ibe_server])
AM_CONDITIONAL([ENABLE_IBE_SERVER], [test "x$enable_ibe_server" != "xno"])
if test x$enable_ibe_server = xno; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_IBE_SERVER"])
fi


# Switches to disable individual schemes
AC_ARG_ENABLE([kem_kyber],
    AC_HELP_STRING([--enable-kem-kyber], [Enable support for the Kyber KEM scheme (default: enable)]),
    [enable_kem_kyber=$enableval],
    [enable_kem_kyber=$enable_kem])

AC_ARG_ENABLE([enc_kyber],
    AC_HELP_STRING([--enable-enc-kyber], [Enable support for the Kyber Encryption scheme (default: enable)]),
    [enable_enc_kyber=$enableval],
    [enable_enc_kyber=$enable_encryption])

AM_CONDITIONAL([WITH_KYBER_ENC], [test "x${enable_enc_kyber}" = "xyes"])
AM_CONDITIONAL([WITH_KYBER_KEM], [test "x${enable_kem_kyber}" = "xyes"])
if test "x${enable_kem_kyber}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_KEM_KYBER"])
fi
if test "x${enable_enc_kyber}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_ENC_KYBER"])
fi

AC_ARG_ENABLE([enc_rlwe],
    AC_HELP_STRING([--enable-enc-rlwe], [Enable support for the RLWE Encryption scheme (default: enable)]),
    [enable_enc_rlwe=$enableval],
    [enable_enc_rlwe=$enable_encryption])
AM_CONDITIONAL([WITH_RLWE_ENC], [test "x${enable_enc_rlwe}" = "xyes"])
if test "x${enable_enc_rlwe}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_ENC_RLWE"])
fi

AC_ARG_ENABLE([sig_dilithium],
    AC_HELP_STRING([--enable-sig-dilithium], [Enable support for the Dilithium Signature scheme (default: enable)]),
    [enable_sig_dilithium=$enableval],
    [enable_sig_dilithium=$enable_signatures])
AM_CONDITIONAL([WITH_DILITHIUM_SIG], [test "x${enable_sig_dilithium}" = "xyes"])
if test "x${enable_sig_dilithium}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_DILITHIUM"])
fi

AC_ARG_ENABLE([sig_dilithium_g],
    AC_HELP_STRING([--enable-sig-dilithium-g], [Enable support for the Dilithium Signature scheme (default: enable)]),
    [enable_sig_dilithium_g=$enableval],
    [enable_sig_dilithium_g=$enable_signatures])
AM_CONDITIONAL([WITH_DILITHIUM_G_SIG], [test "x${enable_sig_dilithium_g}" = "xyes"])
if test "x${enable_sig_dilithium_g}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_DILITHIUM_G"])
fi

AM_CONDITIONAL([BUILD_DILITHIUM], [test "x${enable_sig_dilithium}" = "xyes" || test "x${enable_sig_dilithium_g}" = "xyes"])

AC_ARG_ENABLE([sig_bliss_b],
    AC_HELP_STRING([--enable-sig-bliss-b], [Enable support for the BLISS-B Signature scheme (default: enable)]),
    [enable_sig_bliss_b=$enableval],
    [enable_sig_bliss_b=$enable_signatures])
AM_CONDITIONAL([WITH_BLISS_B_SIG], [test "x${enable_sig_bliss_b}" = "xyes"])
if test "x${enable_sig_bliss_b}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_BLISS_B"])
fi

AC_ARG_ENABLE([sig_ring_tesla],
    AC_HELP_STRING([--enable-sig-ring-tesla], [Enable support for the Ring-TESLA Signature scheme (default: enable)]),
    [enable_sig_ring_tesla=$enableval],
    [enable_sig_ring_tesla=$enable_signatures])
AM_CONDITIONAL([WITH_RING_TESLA_SIG], [test "x${enable_sig_ring_tesla}" = "xyes"])
if test "x${enable_sig_ring_tesla}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_RING_TESLA"])
fi

AC_ARG_ENABLE([kem_ens],
    AC_HELP_STRING([--enable-kem-ens], [Enable support for the ENS KEM scheme (default: enable)]),
    [enable_kem_ens=$enableval],
    [enable_kem_ens=$enable_kem])
AM_CONDITIONAL([WITH_ENS_KEM], [test "x${enable_kem_ens}" = "xyes"])
if test "x${enable_kem_ens}" = "xno"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_KEM_ENS"])
fi

AC_ARG_ENABLE([ibe_dlp],
    AC_HELP_STRING([--enable-ibe-dlp], [Enable support for the DLP IBE scheme (default: enable)]),
    [enable_ibe_dlp=$enableval],
    [enable_ibe_dlp=$enable_ibe])

AC_ARG_ENABLE([sig_dlp],
    AC_HELP_STRING([--enable-sig-dlp], [Enable support for the DLP Signature scheme (default: enable)]),
    [enable_sig_dlp=$enableval],
    [enable_sig_dlp=$enable_signatures])

AC_ARG_ENABLE([sig_ens],
    AC_HELP_STRING([--enable-sig-ens], [Enable support for the ENS Signature scheme (default: enable)]),
    [enable_sig_ens=$enableval],
    [enable_sig_ens=$enable_signatures])

if test "x${enable_sig_ens}" != "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_ENS"])
fi

if test "x${enable_ibe_dlp}" != "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_IBE_DLP"])
fi

if test "x${enable_sig_dlp}" != "xyes"; then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DDISABLE_SIG_DLP"])
fi

AM_CONDITIONAL([WITH_DLP_IBE], [test "x${enable_ibe_dlp}" = "xyes"])
AM_CONDITIONAL([WITH_DLP_SIG], [test "x${enable_sig_dlp}" = "xyes"])
AM_CONDITIONAL([WITH_ENS_SIG], [test "x${enable_sig_ens}" = "xyes"])
AM_CONDITIONAL([BUILD_DLP_ENS_SIG], [test "x${enable_sig_ens}" = "xyes" || test "x${enable_sig_dlp}" = "xyes"])


# Determine which of the sub-functions are required
AM_CONDITIONAL([WITH_ARITH_MLWE],
  [test "x${enable_kem_kyber}" = "xyes" ||
   test "x${enable_enc_kyber}" = "xyes" ||
   test "x${enable_sig_dilithium}" = "xyes" ||
   test "x${enable_sig_dilithium_g}" = "xyes"])
AM_CONDITIONAL([WITH_ARITH_MP],
  [test "x${enable_ibe_dlp}" = "xyes" ||
   test "x${enable_sig_ens}" = "xyes" ||
   test "x${enable_sig_dlp}" = "xyes"])
AM_CONDITIONAL([WITH_ARITH_GPV],
  [test "x${enable_ibe_dlp}" = "xyes" ||
   test "x${enable_sig_ens}" = "xyes" ||
   test "x${enable_sig_dlp}" = "xyes"])


# Disable support for the x87 FPU on 386 as gcc optimisation is proving dangerous - use
# SSE instructions instead
if test "x${simd_arch}" = "xi386"; then
  AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -mfpmath=sse"])
fi


# If the platform supports loop vectorisation then enable gcc's automatic
# loop vectorisation functionality
if test "x${enable_simd}" != "xno"; then
  AC_SUBST([AM_CFLAGS], ["-ftree-vectorize $AM_CFLAGS"])
fi

AC_ARG_ENABLE([simd_info],
    AC_HELP_STRING([--enable-simd-info], [Enable output of SIMD information (default: enable)]),
    [enable_simd_info=$enableval],
    [enable_simd_info="yes"])
if test "x${enable_simd}" = "xyes" && test "x${enable_simd_info}" = "xyes"; then
    AC_SUBST([AM_CFLAGS], ["-fopt-info-vec $AM_CFLAGS"])
fi

# Add support for fast_math
#if test "x${enable_x86_simd}" = "xyes"; then
#    AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -fopenmp"])
#fi
#AC_SUBST([AM_CFLAGS], ["$AM_CFLAGS -ffast-math"])


# Check for 64-bit type support
AC_CHECK_TYPE([int64_t],
  [have_int64_t=yes],
  [have_int64_t=no], [])
AC_CHECK_TYPE([uint64_t],
  [have_uint64_t=yes],
  [have_uint64_t=no], [])
if test x$have_int64_t = xyes; then
  if test x$have_uint64_t = xyes; then
    AC_DEFINE(HAVE___INT64_T, 1, [Have 64-bit types])
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_64BIT"])
  else
    AC_MSG_ERROR([This library currently requires support for 64-bit types.])
  fi
fi
AM_CONDITIONAL([HAVE_64BIT], [test x$have_uint64_t = xyes])

# Check for 128-bit type support
AC_ARG_ENABLE([128bit], AC_HELP_STRING([--enable-128bit], [Disable support for 128-bit types]))
if test "x${enable_128bit}" != "xno"; then
  AC_CHECK_TYPE([__int128_t],
    [have_int128_t=yes],
    [have_int128_t=no], [])
  AC_CHECK_TYPE([__uint128_t],
    [have_uint128_t=yes],
    [have_uint128_t=no], [])
  if test x$have_int128_t = xyes; then
    if test x$have_uint128_t = xyes; then
      AC_DEFINE(HAVE___INT128_T, 1, [Have 128-bit types])
      AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_128BIT"])
    fi
  fi
else
  have_int128_t=no
fi
AM_CONDITIONAL([HAVE_128BIT], [test x$have_uint128_t = xyes])

# Check for float 128-bit type support (IEEE754)
AC_CHECK_TYPE([float128_t],
  [have_float128_t=yes],
  [have_float128_t=no], [])
if test x$have_float128_t = xyes; then
  AC_DEFINE(HAVE___FLOAT128_T, 1, [Have float128_t types])
  AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_FLOAT128"])
fi
AM_CONDITIONAL([HAVE_FLOAT128], [test x$have_float128_t = xyes])



# Check for gcc built-in functions
AC_ARG_ENABLE([gcc-builtin], AC_HELP_STRING([--enable-gcc-builtin], [Disable support for gcc builtins, default: true]))
if test "x${enable_gcc_builtin}" != "xno"; then

AC_CACHE_CHECK([for __builtin_bswap32], ac_cv_have___builtin_bswap32,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_bswap32(1)]])],
               [ac_cv_have___builtin_bswap32="yes"], [ac_cv_have___builtin_bswap32="no"]))
if test "$ac__cvhave___builtin_bswap32" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_BSWAP32"])
fi

AC_CACHE_CHECK([for __builtin_bswap64], ac_cv_have___builtin_bswap64,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_bswap32(1)]])],
               [ac_cv_have___builtin_bswap64="yes"], [ac_cv_have___builtin_bswap64="no"]))
if test "$ac__cvhave___builtin_bswap64" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_BSWAP64"])
fi

AC_CACHE_CHECK([for __builtin_clz], ac_cv_have___builtin_clz,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_clz(1)]])],
               [ac_cv_have___builtin_clz="yes"], [ac_cv_have___builtin_clz="no"]))
if test "$ac_cv_have___builtin_clz" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CLZ"])
fi

AC_CACHE_CHECK([for __builtin_clzl], ac_cv_have___builtin_clzl,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_clzl(1)]])],
               [ac_cv_have___builtin_clzl="yes"], [ac_cv_have___builtin_clzl="no"]))
if test "$ac_cv_have___builtin_clzl" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CLZL"])
fi

AC_CACHE_CHECK([for __builtin_clzll], ac_cv_have___builtin_clzll,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_clzll(1)]])],
               [ac_cv_have___builtin_clzll="yes"], [ac_cv_have___builtin_clzll="no"]))
if test "$ac_cv_have___builtin_clzll" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CLZLL"])
fi

AC_CACHE_CHECK([for __builtin_ctz], ac_cv_have___builtin_ctz,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_ctz(1)]])],
               [ac_cv_have___builtin_ctz="yes"], [ac_cv_have___builtin_ctz="no"]))
if test "$ac_cv_have___builtin_ctz" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CTZ"])
fi

AC_CACHE_CHECK([for __builtin_ctzl], ac_cv_have___builtin_ctzl,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_ctzl(1)]])],
               [ac_cv_have___builtin_ctzl="yes"], [ac_cv_have___builtin_ctzl="no"]))
if test "$ac_cv_have___builtin_ctzl" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CTZL"])
fi

AC_CACHE_CHECK([for __builtin_ctzll], ac_cv_have___builtin_ctzll,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_ctzll(1)]])],
               [ac_cv_have___builtin_ctzll="yes"], [ac_cv_have___builtin_ctzll="no"]))
if test "$ac_cv_have___builtin_ctzll" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_CTZLL"])
fi

AC_CACHE_CHECK([for __builtin_parity], ac_cv_have___builtin_parity,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_parity(1)]])],
               [ac_cv_have___builtin_parity="yes"], [ac_cv_have___builtin_parity="no"]))
if test "$ac_cv_have___builtin_parity" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_PARITY"])
fi

AC_CACHE_CHECK([for __builtin_parityl], ac_cv_have___builtin_parityl,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_parityl(1)]])],
               [ac_cv_have___builtin_parityl="yes"], [ac_cv_have___builtin_parityl="no"]))
if test "$ac_cv_have___builtin_parityl" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_PARITYL"])
fi

AC_CACHE_CHECK([for __builtin_parityll], ac_cv_have___builtin_parityll,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_parityll(1)]])],
               [ac_cv_have___builtin_parityll="yes"], [ac_cv_have___builtin_parityll="no"]))
if test "$ac_cv_have___builtin_parityll" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_PARITYLL"])
fi

AC_CACHE_CHECK([for __builtin_popcount], ac_cv_have___builtin_popcount,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_popcount(1)]])],
               [ac_cv_have___builtin_popcount="yes"], [ac_cv_have___builtin_popcount="no"]))
if test "$ac_cv_have___builtin_popcount" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_POPCOUNT"])
fi

AC_CACHE_CHECK([for __builtin_popcountl], ac_cv_have___builtin_popcountl,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_popcountl(1)]])],
               [ac_cv_have___builtin_popcountl="yes"], [ac_cv_have___builtin_popcountl="no"]))
if test "$ac_cv_have___builtin_popcountl" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_POPCOUNTL"])
fi

AC_CACHE_CHECK([for __builtin_popcountll], ac_cv_have___builtin_popcountll,
               AC_LINK_IFELSE([AC_LANG_PROGRAM(,[[return __builtin_popcountll(1)]])],
               [ac_cv_have___builtin_popcountll="yes"], [ac_cv_have___builtin_popcountll="no"]))
if test "$ac_cv_have___builtin_popcountll" = "yes"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE___BUILTIN_POPCOUNTLL"])
fi

fi


# Check for generic platform bitwidth
AC_CHECK_SIZEOF([size_t])
if test "$ac_cv_sizeof_size_t" = "8"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_SIZE_T_8BYTES"])
fi
AC_CHECK_SIZEOF([long])
if test "$ac_cv_sizeof_long" = "8"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_LONG_8BYTES"])
fi
AC_CHECK_SIZEOF([int])
if test "$ac_cv_sizeof_unsigned_long" = "8"
then
    AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -DHAVE_INT_8BYTES"])
fi


###############################################################################
#                                  TESTING
###############################################################################

AC_ARG_WITH([tests], AC_HELP_STRING([--without-tests], [Do not build tests]))

AM_CONDITIONAL([HAVE_CHECK], [test "x${with_tests}" != "xno"])
AS_IF([test "x${with_tests}" != "xno"], [
  PKG_CHECK_MODULES([CHECK], [check >= 0.9.10])
])
AS_IF([test "x${with_tests}" = "xno"], [
  AC_MSG_WARN([tests disabled.])
])


###############################################################################
#                                    ZIP
###############################################################################

# Check for the presence of zip/unzip
AC_CHECK_PROG([ZIP], zip, zip)
if test -z "$ZIP"; then
  AC_MSG_ERROR([zip/unzip not found.])
fi


###############################################################################
#                                  PDFLATEX
###############################################################################

# Check for the presence of pdfLaTeX
AC_CHECK_PROG(PDFLATEX, pdflatex, pdflatex)
if test -z "$PDFLATEX"; then
  AC_MSG_WARN([pdfLaTeX not found - continuing without documentation PDF generation.])
fi
AM_CONDITIONAL([HAVE_PDFLATEX], test -n "$PDFLATEX")


###############################################################################
#                                   DOXYGEN
###############################################################################

# Check for the presence of Doxygen
AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen])
if test -z "$DOXYGEN"; then
   AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxygen/Doxyfile])])

# Doxygen features
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
DX_PS_FEATURE(OFF)

# Doxygen build configuration
DX_INIT_DOXYGEN([$PACKAGE_NAME], [docs/Doxygen/Doxyfile], [docs/Doxygen/build])


###############################################################################
#                              C STATIC ANALYSIS
###############################################################################

# Check for the presence of Splint
AC_CHECK_PROGS([SPLINT], [splint])
if test -z "$SPLINT"; then
   AC_MSG_WARN([Splint not found - continuing without Splint C static analysis support])
fi
AM_CONDITIONAL([HAVE_SPLINT], [test -n "$SPLINT"])


###############################################################################
#                                    OUTPUT
###############################################################################

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile docs/Doxygen/Makefile \
    build_tools/Makefile \
    build_tools/ntt_table_gen/Makefile \
    src/Makefile \
    src/schemes/Makefile \
    src/schemes/helloworld/Makefile \
    src/utils/Makefile \
    src/utils/arith/Makefile \
    src/utils/crypto/Makefile \
    src/utils/crypto/unit/Makefile \
    src/utils/sampling/Makefile \
    src/utils/entropy/Makefile \
    src/utils/third_party/Makefile \
    src/unit/Makefile \
    test/Makefile \
    test/functional/Makefile \
    test/kat/Makefile \
    bindings/Makefile \
    bindings/c++/Makefile \
    bindings/csharp/Makefile \
    bindings/python/Makefile \
    bindings/helloworld/Makefile])
if test "x${enable_encryption}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/enc/Makefile])
fi
if test "x${enable_signatures}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/sig/Makefile])
fi
if test "x${enable_ibe}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/ibe/Makefile])
fi
if test "x${enable_kem}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/kem/Makefile])
fi
AC_MSG_NOTICE(enable_kem_kyber = ${enable_kem_kyber})
if test "x${enable_multithreading}" = "xyes"; then
    AC_CONFIG_FILES([src/utils/threading/Makefile])
fi
if test "x${enable_kem_kyber}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/kem/kyber/Makefile])
fi
if test "x${enable_ibe_dlp}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/ibe/dlp/Makefile])
fi
if test "x${enable_sig_ens}" = "xyes" || test "x${enable_sig_dlp}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/sig/ens_dlp/Makefile])
fi
if test "x${enable_enc_kyber}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/enc/kyber/Makefile])
fi
if test "x${enable_sig_dilithium}" = "xyes" || test "x${enable_sig_dilithium_g}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/sig/dilithium/Makefile])
fi
if test "x${enable_sig_bliss_b}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/sig/bliss_b/Makefile])
fi
if test "x${enable_sig_ring_tesla}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/sig/ring_tesla/Makefile])
fi
if test "x${enable_enc_rlwe}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/enc/rlwe_enc/Makefile])
fi
if test "x${enable_kem_ens}" = "xyes"; then
    AC_CONFIG_FILES([src/schemes/kem/ens/Makefile])
fi

AC_CONFIG_SUBDIRS([src/utils/crypto])
#AX_SUBDIRS_CONFIGURE([src/utils/crypto])
AC_OUTPUT
