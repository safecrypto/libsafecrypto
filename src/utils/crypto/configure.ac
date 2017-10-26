###############################################################################
#                              AUTOTOOLS SETUP
###############################################################################

AC_PREREQ([2.69])

AC_INIT([SAFEcrypto HashRNG], 1.0.0, [n.smyth@qub.ac.uk])

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

# AC_CANONICAL_HOST is needed to access the 'host_os' variable    
AC_CANONICAL_HOST


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



AM_INIT_AUTOMAKE([1.13.4 subdir-objects foreign -Wall -Werror -Wno-portability])
AM_SILENT_RULES([yes])

AM_PATH_PYTHON(,, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])


if test -z $CFLAGS; then
    CFLAGS='-O2'
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


AC_SUBST([AM_CPPFLAGS], ["$AM_CPPFLAGS -D_GNU_SOURCE"])

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
        AC_MSG_WARN([SIMD support not available for this CPU.  Performance will suffer.])
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


# Constrained system enable/disable
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


# Disable support for the x87 FPU on 386 as gcc optimisation is
# proving dangerous - use SSE instructions instead
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
AC_CONFIG_FILES([Makefile unit/Makefile])
AC_OUTPUT
