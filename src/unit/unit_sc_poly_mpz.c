/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <stdlib.h>
#include <check.h>
#include "safecrypto.h"
#include "safecrypto_private.h"
#include "safecrypto_version.h"
#include "utils/arith/arith.h"
#include "utils/arith/sc_mpz.c"
#include "utils/arith/sc_poly_mpz.c"
#include "utils/crypto/prng.c"
#include "utils/sampling/gaussian_cdf.c"


SINT32 test_int_f[512] = {
    683,   -383,   1636,   -444,   2202,     98,   -505,    984,  -1296,   2495,     68,   -526,   1041,   -572,  -1291,    468,
  -1182,   -211,  -1157,    402,    221,   -688,    626,    776,   2155,   1075,    203,  -1121,   1953,  -1183,   1538,    971,
    856,   -889,   -329,  -1592,    -73,   1524,   2311,   -856,   -207,   -634,   1285,   2091,   1714,   1926,   1205,    715,
   1054,  -1067,    470,  -1465,  -1207,   1506,  -1095,    945,    346,   2593,   -309,    538,    413,   -146,   -561,  -1612,
   -835,      0,    453,   -719,   1932,  -1910,     10,    272,   -669,    682,   1163,  -1233,   -947,   -173,   -747,    104,
   -836,   1854,   1205,    341,     96,   -586,  -1108,    730,   -908,    758,   -810,    460,   1210,   -300,      0,   1105,
   -918,   2339,  -2084,  -1269,    553,    -47,    882,   -159,   1230,   -505,    -40,    806,    342,  -2869,   -635,   1570,
    540,   -682,   -800,   -494,    619,    699,    747,   1325,   -139,    373,   -388,  -1126,    310,   -550,  -1316,   -470,
    -87,  -1295,   1823,   -367,   -457,   -264,   1253,   1537,   -500,   1863,   -134,   -590,  -1097,   -647,  -1399,    401,
   1196,    948,  -1137,    603,   2718,   -126,   -861,     18,   -340,   -217,   -723,    485,   1357,    263,   -215,  -2076,
     34,   -248,   -442,  -1402,    533,   -631,  -1875,  -2186,     49,   -891,    224,    662,  -1450,   -406,  -1063,   1128,
  -2159,   -789,  -1136,    -73,  -1601,    761,  -1631,   1935,  -2104,    159,   -665,   -838,  -1399,     34,  -1270,   -454,
    322,    465,   -294,   1170,  -1169,   1437,    639,    155,     -9,    473,   2533,    272,    -12,   -187,   -748,   1301,
  -1168,    342,   -456,  -3192,   -982,   -105,   2316,   -326,  -2073,    191,    203,   -592,   -975,    258,    711,   -403,
    474,     70,    304,   -332,   -253,   -453,   1223,    719,   -999,    998,   -983,  -2203,   1262,   -491,    692,    416,
   1028,   1131,   -213,    443,    121,    608,    -53,  -1813,   -952,     99,   1418,    354,   1645,    284,    -88,    818,
   -869,   1210,  -2104,   1142,    233,  -1475,   2662,   1711,    962,    607,   -778,    291,   -873,   -502,   2418,  -1971,
   -637,    542,   -762,  -1797,   -869,  -2041,  -2532,   2097,  -1089,   1733,  -1171,   -565,    -56,  -2339,   -938,  -1203,
   -152,     30,    867,   1078,   -850,    574,  -1509,  -1068,    240,   -147,   1162,   -443,  -1443,  -1730,  -1581,   -177,
    329,     50,   1183,    247,   -788,    315,   -855,    225,    760,    504,   2292,    651,  -1359,   1105,   1143,  -1188,
  -1431,   -923,   -947,   1649,   -694,   2610,    781,   -756,   -428,   -993,    308,  -1185,  -2657,   -664,   -157,   -290,
    341,    557,   -587,   1509,   -341,     82,  -1001,   1203,    565,   1208,    -55,   -393,   2541,  -1843,  -1157,  -1536,
    -54,   1361,   2549,   1933,    -61,  -1844,    972,   -869,   -332,  -1524,   1344,    170,  -1890,    818,   1013,  -3265,
   2363,  -1992,     84,   -408,   1644,   1624,   1020,   -857,  -1513,     98,   -532,   -255,   -138,   1555,   1541,   -567,
     52,   -230,  -3595,   -727,   -357,   -641,    624,  -1916,   1647,   -667,  -1230,  -1516,   -512,    699,  -2029,  -2126,
    678,  -1230,   -839,    114,    906,   1442,   -437,    -23,   -712,  -1094,  -2883,    -70,   -535,   1923,   -714,   -586,
  -2011,   -223,  -2815,    689,    591,     91,     79,    213,    501,   1888,    610,   -879,    325,  -1281,    -35,  -1424,
   -192,   1644,   -584,    343,   2250,   -330,   1281,  -1409,    854,   -470,   3246,   -586,   1520,   -240,    696,    534,
   1514,     30,  -1390,   -677,    576,  -2520,  -1265,   -986,   -121,  -1392,    300,    645,     85,   -228,   -956,   2115,
  -1591,     55,    726,  -1929,  -1939,   -699,  -2062,    901,    254,   1044,    405,  -2558,    855,   -629,  -2614,   -163,
    477,   1794,    251,  -1240,   -214,    296,    750,    665,    683,   1617,   -468,   -148,  -1514,    428,     34,   1037,
    351,   1157,   -895,   1716,   1260,     56,    293,    110,   -332,   -457,     73,  -1079,    489,    400,  -2248,    303
};
SINT32 test_int_f2[512] = {
  159, -28, -36, -129, -329, 55, 24, 9, -105, 43, -267, -163, 158, -110, 233, 319, -269, -253, -158, -137, -239, 1, 396, -842, -1, 173, -300, 537, 331, -275, -138, -99, -238, -176, 225, 101, 102, 215, 127, 128, 8, -144, 216, -85, 136, -111, -112, 124, 31, -96, -178, 144, -159, -257, -169, 70, 132, 74, -346, 139, -466, -209, -55, 235, -495, 162, 13, 394, 53, -266, 31, -100, 145, -436, 157, 159, 3, -210, -368, -370, 71, 28, -8, 215, -150, -215, 30, 78, -248, -162, 174, -476, -523, -177, 375, -253, -243, -49, -300, -297, -63, 123, -235, -156, 318, -16, -90, -123, -35, -21, 44, 42, 43, -10, 0, -209, -339, -63, 317, -521, 469, 69, -121, -8, 298, 119, -463, 222, -501, -53, -280, 32, -176, 385, 257, -203, -136, 108, 172, 267, 300, -80, 70, -64, -390, 275, 207, 354, -256, -157, 236, 237, 67, 87, 100, 184, 267, 336, -337, -228, -228, -234, 357, 176, 270, 209, 20, -667, 421, 281, 253, 77, 176, -396, 222, -213, -126, 294, 167, -229, 260, -432, 99, 20, -47, -521, 114, 223, 169, -126, 348, -563, -92, -78, -319, -306, 29, 64, 233, -284, -116, -416, -165, -79, -129, -151, -58, -120, -71, -357, -334, 192, -101, 95, -70, 392, -225, 284, -210, -191, 357, 88, -374, 225, -342, -405, -159, -26, 97, -355, 90, 38, 520, -24, 115, -350, 306, 58, 90, 37, 183, -344, 210, -112, -305, -183, 572, 253, 200, 58, -125, -124, 63, 151, 131, 134, -2, 54, 127, -385, 166, 155, 64, 75, 395, -77, 171, -210, -45, -408, -275, -130, 229, -128, -36, 306, 223, 258, 114, 75, -513, 442, -163, -431, 82, 221, 145, 329, 495, -69, -132, 442, 210, 211, -49, -26, -187, 154, -135, 254, -330, 138, -180, -119, 99, -14, -59, -303, 33, -344, -489, -39, 191, 74, 263, 263, 124, -98, 14, 298, -48, 68, -116, 154, -14, 43, 49, -6, -85, -140, -344, -152, -33, 221, 18, -137, 18, -31, 69, 88, 165, -228, 421, -78, -18, -97, -191, 135, 321, 32, -499, 178, 236, 312, -452, -290, -253, -35, -701, -185, -161, -102, 288, -30, 63, -87, -33, 228, -42, 62, -330, -116, 218, -132, -173, -196, -5, -50, -194, 203, 149, 65, 59, -220, -60, -260, 452, 42, 128, -236, -142, 539, 57, -288, 106, -139, 227, 336, 557, 133, 463, 104, -56, 285, -405, -319, 59, -234, 221, -10, -165, -11, 431, 381, 457, 3, 290, -104, 154, -431, 253, 219, 331, -95, 252, 434, -134, 90, -92, 28, -105, -72, 296, 76, 123, 234, -307, -433, -248, 138, -90, -121, 187, -27, 80, 200, -199, -45, -67, 241, 195, -63, 218, -717, 13, 24, -64, -21, -254, 17, 218, 653, -286, -164, -159, -346, 5, -265, -166, 222, -25, 75, -551, -265, 206, -20, -179, -51, 333, -14, -30, -65, -231, -132, 131, -177, 18, -40, 177, 32, 134, -325, -26, -32, -222, 280, -319, -139, 390, -212, 232, 297, -58, 140, -244, -304, -24, -175, 34, -109, 142, 159
};
SINT32 test_int_g[512] = {
     50,  -1764,   -937,   -409,    123,  -1547,    260,    532,  -1633,   -548,    594,    553,   -360,   2805,    770,    543,
   -344,   2507,     28,     68,   -874,    308,  -2794,    657,   -228,  -2010,     12,   -925,    862,    142,  -1520,   2279,
    213,     91,   2954,   -208,    715,   -724,  -1377,    679,   1065,   1241,   1305,     19,   -188,   1250,  -1069,  -2162,
   1641,   1310,   1217,   1097,   -633,    887,   -993,   -448,   1108,     73,  -2070,   2990,    483,  -1197,   -809,   1178,
   -382,   -573,   -474,  -1848,  -1610,   1055,   -847,   1297,    367,    740,    485,     20,  -1266,   -295,    407,  -1631,
    601,   1559,    606,  -1763,   -159,  -1220,   -593,   -646,   -343,  -2168,  -2546,   -495,   -812,    476,   1198,   -883,
    113,  -2097,     50,  -2213,   -466,   -701,  -1631,   1780,  -1743,  -1137,     91,  -1209,    751,   1091,    333,   2182,
   -725,   -740,   -683,    962,    828,   -723,   -774,    458,    800,   -341,  -1402,   -824,    181,   -344,    794,    957,
  -2518,   2445,   -376,   1418,   1472,   -467,   1007,   1322,   -194,  -1313,    775,    250,   -132,   1862,   2565,    102,
    479,   -228,   -106,    517,    187,    661,   -798,  -1563,   -571,    134,    910,     63,   -397,   -146,   -711,   1021,
  -2002,    695,   -854,   1030,    404,   -235,  -1160,   1148,   1090,    384,    466,    135,   1201,     99,   1597,    568,
    -82,  -1707,   -461,   1455,   -878,    988,   -162,   1149,  -2626,    232,    497,   -528,   -153,  -1421,    239,    435,
   2234,     56,  -2026,  -2090,   -596,   2136,    552,    535,   -766,    266,   2299,  -1007,    509,  -2171,    893,  -1879,
    737,    924,    618,    -94,   1143,   -155,    994,    -64,   -232,  -1405,  -1185,    464,  -1473,    391,    400,   2125,
    782,    314,  -1153,   1063,   1420,    842,   -665,    469,   -619,  -1362,   2316,   -591,   -709,    895,    830,    416,
   1335,  -2697,   -785,   -995,   -857,   1341,    -38,  -1989,    521,  -2000,   1326,    -86,   -981,    623,   2080,   1075,
   1607,   -379,  -1030,   -816,    250,    240,  -2755,     36,  -1824,   1052,    483,   -309,     15,    825,  -2252,   1208,
   -339,      5,   1534,    356,  -2533,     90,   -591,  -1202,   -291,   1189,  -1360,    813,  -1176,    996,  -2027,   -182,
    576,  -1485,   -613,  -1093,  -1147,  -1093,   -554,    666,    510,   -819,    394,   -143,    685,  -1106,   1623,   -511,
   -358,  -1072,   2797,    249,   -272,    679,    381,  -1409,    -67,   -634,  -3065,  -2340,  -1438,   -414,   -413,   1307,
    -22,     45,    -95,   -227,  -1802,   1878,    319,   -539,  -1096,  -2703,   1352,     96,   -743,     31,    -11,   -574,
     83,   1190,   2098,    427,    387,    703,   1000,  -1345,   -521,   1993,   1443,  -2834,   2261,  -1268,   -365,   -862,
    638,   -322,   -208,    613,  -1011,    -87,  -1387,   -599,   -942,   -646,   -187,    809,   2729,   1648,  -1715,    812,
  -1250,  -1391,   -343,   -930,    910,   -564,   -184,    562,    924,    324,    741,  -1439,   1530,  -1594,   -225,   -817,
   1586,     17,     76,    468,  -1303,  -1179,   1070,   -129,    437,   -401,   1061,   -107,  -1237,    333,    151,   1380,
  -2393,    629,    108,   -255,   -121,    -12,    -69,   2034,   1877,  -1782,    700,   1517,  -1545,   -370,   1381,    425,
  -1275,  -1370,    -48,   1263,   -344,   -245,  -1467,   -118,     -9,   1442,  -1677,    429,  -1796,  -2122,  -1277,   -285,
    924,   1306,   -684,    539,   -962,    619,    330,   2195,   -515,  -1048,   -477,   2720,    750,   1113,  -1494,    130,
   -294,    219,   1204,   1927,    955,    587,  -1087,    930,  -1052,    487,   1805,   1064,    653,      0,    745,    534,
  -1755,   -532,    778,   1665,   -475,    808,  -2263,  -1091,   -656,   -900,    183,    559,    324,   -729,   1081,    103,
    -37,   -982,    685,  -1705,    -33,  -1058,   2990,    652,  -2603,  -1282,   2977,    -97,  -1006,    205,   1425,    144,
   -579,    516,    459,    -61,   -993,   -991,   -177,   -635,   -815,   -901,   -623,    169,   1407,   -891,    333,   1961
};
SINT32 test_int_g2[512] = {
  -162, -408, 387, -106, -98, 547, -181, -474, -118, 496, -44, -59, 129, 24, -98, -381, 123, 381, -184, -28, -283, 60, -155, 132, 433, -86, 454, -64, 123, -500, 168, 451, 364, 180, -76, 283, -623, -105, 578, 311, -183, -68, -153, 216, 47, 640, -232, 298, 0, 189, 212, -228, -277, 177, -199, 95, -377, -53, 127, 220, -718, -390, -126, -263, 119, -67, 628, -224, 36, -75, 262, 213, 113, -93, 229, 143, 313, 295, -135, 253, 139, -76, -268, 115, -110, 136, -129, 42, 260, -27, -85, -27, 255, -165, -147, -354, -356, 411, 163, 4, -309, 295, 252, -272, -276, -422, -148, 137, -273, 251, -284, -61, 421, 529, -45, 23, -321, -258, -4, -186, 417, 28, 320, 148, -56, 399, -156, -230, -21, 139, -153, 261, 102, 29, 57, -260, -95, -9, 367, 188, 540, -674, 134, 322, 132, 295, -397, 76, -474, 365, -186, -186, 385, 52, -36, 92, -164, 293, 463, 50, -252, -198, 206, 622, -77, 98, -99, -51, 128, -82, 280, 159, -253, -212, 265, -10, 117, 211, -439, 49, 289, -310, 444, -243, 480, -195, -22, -14, 140, -50, 204, -548, -165, -300, 365, 92, -162, 147, 81, -59, 231, -149, 559, -201, 422, -349, -392, -383, -402, -198, 40, -116, -105, -219, -12, -111, -655, 314, 13, -541, 442, 70, 17, -242, -245, 132, 278, -114, -38, -1, 286, -81, -235, 55, -123, 41, -387, 162, -329, 157, -148, 129, 38, 439, 92, -160, 35, 293, 145, -238, 0, -31, 167, 314, 347, 367, 599, 75, 211, 286, -42, -236, 64, 81, -149, 87, -221, -244, 191, 289, -146, 295, 121, -186, 228, 29, -88, 138, 148, -565, -52, 347, -329, -35, 162, 154, -94, -775, -16, -108, 347, 389, 209, 71, -132, 31, -158, 14, -385, -404, 181, -385, -390, -235, 28, 84, -95, -278, 16, 617, 35, -106, -234, 68, 335, 293, 146, 97, 102, 251, -241, 203, 440, -15, -110, -86, 106, 234, -267, -57, -2, 435, 262, 131, 69, -234, -25, 252, 131, -161, -367, 116, -524, 338, -89, 377, -180, 169, -133, -94, 125, -316, -194, 321, 25, 41, -62, 306, -222, 132, -170, 620, -138, -89, -425, 451, 73, 120, -102, -207, 63, -188, 27, -240, 70, 343, -460, 6, 238, 56, -169, -360, -107, -348, 52, 171, 295, 276, -33, -295, 410, 72, 45, 102, -184, 148, -527, -189, 56, -435, -245, 313, 32, 48, 342, -10, 364, -199, -211, -142, 14, -73, -38, 54, 29, -128, -61, 553, 5, -455, 25, -167, -100, 176, -102, 58, 385, 185, 55, 126, 72, -268, -308, 75, 458, -127, 365, -132, 134, -104, -62, -78, -203, -132, -418, 57, 230, 544, 127, -134, -354, -404, -54, -100, 146, 313, 199, -106, 87, -444, 92, 224, 8, 183, -52, -305, -292, -240, 408, -494, 205, -199, -77, 64, 57, -147, 89, 74, -397, -323, -226, -206, 436, 184, -55, 296, -480, -24, -22, 415, 54, -153, 45, 193, -175, -303, -213, 340, -519, -147, 190, 205, -816, -85, -105, 43, 320, -13, 640, 19, -372, -96
};

START_TEST(test_degree)
{
    SINT32 data[4] = {1, 2, 3, 4};
    sc_poly_mpz_t poly;
    sc_poly_mpz_init(&poly, 4);
    sc_poly_mpz_copy_si32(&poly, 4, data);
    SINT32 value;
    value = sc_poly_mpz_degree(NULL);
    ck_assert_int_eq(value, -1);
    value = sc_poly_mpz_degree(&poly);
    ck_assert_int_eq(value, 3);
}
END_TEST

START_TEST(test_div_0)
{
    size_t i;
    SINT32 num_data[4] = {1, 2, 3, 4};
    SINT32 den_data[4] = {2, 0, 0, 0};
    sc_poly_mpz_t num, den, quo, rem, prod;
    sc_poly_mpz_init(&num, 8);
    sc_poly_mpz_init(&den, 4);
    sc_poly_mpz_init(&quo, 4);
    sc_poly_mpz_init(&rem, 8);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_copy_si32(&num, 4, num_data);
    sc_poly_mpz_copy_si32(&den, 4, den_data);

    sc_poly_mpz_div(&num, &den, &quo, &rem);
    sc_poly_mpz_mul(&prod, &den, &quo);
    sc_poly_mpz_add(&prod, &prod, &rem);
    for (i=0; i<8; i++) {
        ck_assert_int_eq(sc_poly_mpz_get_si(&prod, i), sc_poly_mpz_get_si(&num, i));
    }

    sc_poly_mpz_clear(&num);
    sc_poly_mpz_clear(&den);
    sc_poly_mpz_clear(&quo);
    sc_poly_mpz_clear(&rem);
    sc_poly_mpz_clear(&prod);
}
END_TEST

START_TEST(test_div_1)
{
    size_t i;
    SINT32 num_data[4] = {1, 2, 3, 4};
    SINT32 den_data[4] = {0, 0, 2, 0};
    sc_poly_mpz_t num, den, quo, rem, prod;
    sc_poly_mpz_init(&num, 8);
    sc_poly_mpz_init(&den, 4);
    sc_poly_mpz_init(&quo, 4);
    sc_poly_mpz_init(&rem, 8);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_copy_si32(&num, 4, num_data);
    sc_poly_mpz_copy_si32(&den, 4, den_data);

    sc_poly_mpz_div(&num, &den, &quo, &rem);
    sc_poly_mpz_mul(&prod, &den, &quo);
    sc_poly_mpz_add(&prod, &prod, &rem);
    for (i=0; i<8; i++) {
        ck_assert_int_eq(sc_poly_mpz_get_si(&prod, i), sc_poly_mpz_get_si(&num, i));
    }

    sc_poly_mpz_clear(&num);
    sc_poly_mpz_clear(&den);
    sc_poly_mpz_clear(&quo);
    sc_poly_mpz_clear(&rem);
    sc_poly_mpz_clear(&prod);
}
END_TEST

START_TEST(test_div_2)
{
    size_t i;
    SINT32 num_data[4] = {1, 0, 0, 2};
    SINT32 den_data[4] = {7, 0, 0, 0};
    sc_poly_mpz_t num, den, quo, rem, prod;
    sc_poly_mpz_init(&num, 8);
    sc_poly_mpz_init(&den, 4);
    sc_poly_mpz_init(&quo, 4);
    sc_poly_mpz_init(&rem, 8);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_copy_si32(&num, 4, num_data);
    sc_poly_mpz_copy_si32(&den, 4, den_data);

    sc_poly_mpz_div(&num, &den, &quo, &rem);
    sc_poly_mpz_mul(&prod, &den, &quo);
    sc_poly_mpz_add(&prod, &prod, &rem);
    for (i=0; i<8; i++) {
        ck_assert_int_eq(sc_poly_mpz_get_si(&prod, i), sc_poly_mpz_get_si(&num, i));
    }

    sc_poly_mpz_clear(&num);
    sc_poly_mpz_clear(&den);
    sc_poly_mpz_clear(&quo);
    sc_poly_mpz_clear(&rem);
    sc_poly_mpz_clear(&prod);
}
END_TEST

START_TEST(test_div_3)
{
    size_t i;
    sc_poly_mpz_t num, den, quo, rem, prod;
    sc_poly_mpz_init(&num, 128);
    sc_poly_mpz_init(&den, 128);
    sc_poly_mpz_init(&quo, 128);
    sc_poly_mpz_init(&rem, 256);
    sc_poly_mpz_init(&prod, 256);
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_poly_mpz_reset(&rem, 0);

    for (int j=0; j<128; j++) {
        for (i=0; i<128; i++) {
            sc_poly_mpz_set_si(&num, i, prng_32(prng_ctx));
            sc_poly_mpz_set_si(&den, i, (i>=j)? prng_32(prng_ctx) : 0);
        }
        sc_poly_mpz_div(&num, &den, &quo, &rem);
        sc_poly_mpz_mul(&prod, &den, &quo);
        sc_poly_mpz_add(&prod, &prod, &rem);
        for (i=0; i<128; i++) {
            ck_assert_int_eq(sc_poly_mpz_get_si(&prod, i),
                             sc_poly_mpz_get_si(&num, i));
        }
    }

    prng_destroy(prng_ctx);
    sc_poly_mpz_clear(&num);
    sc_poly_mpz_clear(&den);
    sc_poly_mpz_clear(&quo);
    sc_poly_mpz_clear(&rem);
    sc_poly_mpz_clear(&prod);
}
END_TEST

START_TEST(test_xgcd_0)
{
    SINT32 a_data[4] = {4, 8, 0, 8};
    SINT32 b_data[4] = {4, 4, 0, 0};
    sc_mpz_t gcd;
    sc_poly_mpz_t a, b, temp, x, y, prod;
    sc_mpz_init(&gcd);
    sc_poly_mpz_init(&a, 4);
    sc_poly_mpz_init(&b, 4);
    sc_poly_mpz_init(&x, 4);
    sc_poly_mpz_init(&y, 4);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_init(&temp, 8);
    sc_poly_mpz_copy_si32(&a, 4, a_data);
    sc_poly_mpz_copy_si32(&b, 4, b_data);

    SINT32 result = sc_poly_mpz_xgcd(&a, &b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    sc_poly_mpz_mul(&prod, &a, &x);
    sc_poly_mpz_mul(&temp, &b, &y);
    sc_poly_mpz_add(&prod, &prod, &temp);
    ck_assert_int_eq(sc_poly_mpz_get_ui(&prod, 0), sc_mpz_get_ui(&gcd));

    sc_mpz_clear(&gcd);
    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&x);
    sc_poly_mpz_clear(&y);
    sc_poly_mpz_clear(&prod);
    sc_poly_mpz_clear(&temp);
}
END_TEST

START_TEST(test_xgcd_1)
{
    SINT32 a_data[4] = {54, 0, 1, 0};
    SINT32 b_data[4] = {2, 1, 0, 0};
    sc_mpz_t gcd;
    sc_poly_mpz_t a, b, temp, x, y, prod;
    sc_poly_mpz_init(&a, 4);
    sc_poly_mpz_init(&b, 4);
    sc_mpz_init(&gcd);
    sc_poly_mpz_init(&x, 4);
    sc_poly_mpz_init(&y, 4);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_init(&temp, 8);
    sc_poly_mpz_copy_si32(&a, 4, a_data);
    sc_poly_mpz_copy_si32(&b, 4, b_data);

    SINT32 result = sc_poly_mpz_xgcd(&a, &b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_FAILURE);

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_mpz_clear(&gcd);
    sc_poly_mpz_clear(&x);
    sc_poly_mpz_clear(&y);
    sc_poly_mpz_clear(&prod);
    sc_poly_mpz_clear(&temp);
}
END_TEST

START_TEST(test_xgcd_2)
{
    SINT32 a_data[4] = {8, 8, 8, 8};
    SINT32 b_data[4] = {8, 8, 8, 8};
    sc_mpz_t gcd;
    sc_poly_mpz_t a, b, temp, x, y, prod;
    sc_poly_mpz_init(&a, 4);
    sc_poly_mpz_init(&b, 4);
    sc_mpz_init(&gcd);
    sc_poly_mpz_init(&x, 4);
    sc_poly_mpz_init(&y, 4);
    sc_poly_mpz_init(&prod, 8);
    sc_poly_mpz_init(&temp, 8);
    sc_poly_mpz_copy_si32(&a, 4, a_data);
    sc_poly_mpz_copy_si32(&b, 4, b_data);

    SINT32 result = sc_poly_mpz_xgcd(&a, &b, &gcd, &x, &y);
    ck_assert_int_eq(result, SC_FUNC_SUCCESS);
    sc_poly_mpz_mul(&prod, &a, &x);
    sc_poly_mpz_mul(&temp, &b, &y);
    sc_poly_mpz_add(&prod, &prod, &temp);
    ck_assert_int_eq(sc_poly_mpz_get_ui(&prod, 0), sc_mpz_get_ui(&gcd));

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_mpz_clear(&gcd);
    sc_poly_mpz_clear(&x);
    sc_poly_mpz_clear(&y);
    sc_poly_mpz_clear(&prod);
    sc_poly_mpz_clear(&temp);
}
END_TEST

START_TEST(test_content)
{
    size_t i;
    SINT32 data[8] = {3, 6, 9, 12, 24, 27, 30, 30000003};
    sc_poly_mpz_t a;
    sc_mpz_t c;
    sc_mpz_init(&c);
    sc_poly_mpz_init(&a, 8);
    for (i=0; i<8; i++) {
        sc_poly_mpz_set_si(&a, i, data[i]);
    }
    prng_ctx_t *prng_ctx = prng_create(SC_ENTROPY_RANDOM, SC_PRNG_AES_CTR_DRBG,
        SC_PRNG_THREADING_NONE, 0x00100000);
    prng_init(prng_ctx, NULL, 0);

    sc_poly_mpz_content(&c, &a);
    ck_assert_int_eq(3, sc_mpz_get_si(&c));

    prng_destroy(prng_ctx);
    sc_poly_mpz_clear(&a);
    sc_mpz_clear(&c);
}
END_TEST

START_TEST(test_content_scale)
{
    size_t i;
    sc_poly_mpz_t a, b;
    SINT32 data[8] = {3, 6, 9, 12, 24, 27, 30, 30000003};
    SINT32 tv[8] = {1, 2, 3, 4, 8, 9, 10, 10000001};
    sc_mpz_t c;
    sc_poly_mpz_init(&a, 8);
    sc_poly_mpz_init(&b, 8);
    sc_mpz_init(&c);
    for (i=0; i<8; i++) {
        sc_poly_mpz_set_si(&a, i, data[i]);
    }
    sc_mpz_init(&c);
    sc_mpz_set_ui(&c, 3);

    sc_poly_mpz_content_scale(&a, &c, &b);
    for (i=0; i<8; i++) {
        ck_assert_int_eq(tv[i], sc_poly_mpz_get_si(&b, i));
    }

    sc_mpz_clear(&c);
    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
}
END_TEST

static const SINT32 tv_rem[] = {
    -1443575, 654035, -3561679, 502404, -4815564, -887510, 1105546, -2059017,
    2615256, -5216072, -908849, 1161844, -2180790, 970433, 3075484, -660891,
    2515332, 832474, 2664869, -553125, -618614, 1479661, -1198784, -1934126,
    -5079568, -3069565, -782069, 2458499, -4050681, 2067625, -3098975, -2648822,
    -2218501, 1739104, 1008959, 3678503, 646480, -3403833, -5656900, 1224055,
    724704, 1487953, -2696578, -5089923, -4486645, -4848990, -3292418, -1972435,
    -2586037, 2079254, -733259, 3150910, 3157231, -3019767, 2005242, -1792575,
    -1064143, -5933902, -91047, -1115797, -1091438, 203069, 1305366, 3793759,
    2365516, 253005, -1018344, 1479053, -4125279, 3708284, 556250, -614486,
    1421496, -1330429, -2821070, 2419395, 2502455, 675845, 1731675, -7451,
    1847816, -3914484, -3270602, -1131683, -319131, 1288240, 2668342, -1305316,
    1819994, -1428860, 1591206, -788650, -2859460, 307770, 90900, -2484040,
    1728849, -4979918, 3976115, 3484164, -858637, -61903, -1968495, 90186,
    -2716863, 762550, 242935, -1799768, -1013034, 6345886, 2296787, -3336955,
    -1689630, 1369516, 2005046, 1352912, -1241830, -1758909, -1891053, -3204941,
    -89003, -796387, 759205, 2648812, -355702, 1142470, 3125018, 1455308, 337986,
    2937521, -3705719, 272647, 1138537, 731943, -2736752, -3834835, 658289,
    -4036524, -263257, 1366922, 2644826, 1786847, 3340993, -477551, -2810111,
    -2493492, 2268732, -1011033, -6292773, -540306, 1973706, 220419, 758866,
    590836, 1691055, -871211, -3197491, -1002395, 403631, 4731993, 552596,
    547202, 1068760, 3285622, -773378, 1256989, 4406193, 5482253, 552206,
    1988121, -233579, -1556048, 3059014, 1352038, 2512642, -2213655, 4511648,
    2427849, 2792795, 508312, 3621167, -1225625, 3435905, -3855687, 4143487,
    280080, 1446743, 2085319, 3398866, 347465, 2844658, 1405402, -586294,
    -1142886, 520017, -2541078, 2273402, -2876169, -1871883, -542057, -26733,
    -1060577, -5837503, -1378955, -55440, 424012, 1738165, -2698004, 2231461,
    -414912, 921462, 7313784, 3174712, 533586, -5174553, 31100, 4758882,
    198751,-514217, 1269307, 2371176, -284559, -1676502, 690511, -943443,
    -300982, -704602, 654224, 669340, 1095003, -2612045, -1986881, 2027895,
    -1940807, 1907390, 5250193, -2169467, 721382, -1406843, -1144844, -2436992,
    -2853972, 136131, -931325, -406237, -1403447, -65080, 4091683, 2689435,
    65904, -3217661, -1225446, -3805222, -1136867, 111772, -1812200, 1705658,
    -2456773, 4363162, -1929704, -869810, 3245201, -5537251, -4652914, -2681009,
    -1656022, 1565023, -418434, 1874331, 1393015, -5283558, 3698154, 2029189,
    -1025405, 1548750, 4270542, 2498003, 4851475, 6310359, -3946860, 1812681,
    -3565817, 2107309, 1624933, 297083, 5275040, 2817341, 2988558, 706205,
    -21384, -1958106, -2686045, 1584166, -1032802, 3218310, 2858091, -215916,
    257736, -2567635, 643778, 3378093, 4326269, 4078278, 876939, -685961,
    -212087, -2674534, -913705, 1696583, -469356, 1826595, -246735, -1776655,
    -1363272, -5305128, -2157924, 2857779, -2072263, -2904279, 2324295, 3576852,
    2508497, 2408525, -3420011, 1060465, -5656998, -2546518, 1462845, 1191212,
    2361948, -391505, 2570556, 6331991, 2297743, 554128, 699491, -678698,
    -1355459, 1150805, -3214371, 309341, -81013, 2225402, -2401041, -1634629,
    -2886779, -242384, 900129, -5593089, 3373141, 3159365, 3803499, 586800,
    -3043166, -6142535, -5117731, -448571, 4163795, -1626324, 1658996, 1009643,
    3526548, -2559540, -789392, 4197210, -1266194, -2525078, 7032781, -4322729,
    3762027, 414744, 891732, -3572088, -4148884, -2785032, 1617476, 3660895,
    238135, 1166242, 734436, 387489, -3453826, -3935333, 807693, 54905,
    501284, 8151250, 2723581, 1022817, 1549139, -1208529, 4118096, -3121908,
    1000375, 2967141, 3780658, 1610324, -1416216, 4349395, 5394035, -879966,
    2559606, 2258762, -2055, -2071230, -3516134, 545450, 184115, 1607545,
    2675048, 6812466, 1030909, 1223890, -4160799, 1022403, 1533670, 4698286,
    1110637, 6395689, -695927, -1537335, -383641, -205165, -502761, -1190787,
    -4396027, -1943344, 1791162, -464263, 2781213, 466823, 3211757, 863088,
    -3637536, 814700, -594112, -5161929, 60090, -2779698, 2779289, -1492865,
    797798, -7154598, 333790, -3239402, 78960, -1491888, -1411320, -3565274,
    -526182, 3115630, 1943066, -1089717, 5490432, 3607280, 2599823, 570766,
    3165879, -252624, -1540860, -386515, 486789, 2218172, -4464852, 2935723,
    358433, -1648713, 4116414, 4943359, 2158869, 4847173, -1400662, -843995,
    -2423874, -1226772, 5627669, -1146966, 1154927, 6066859, 1158466, -1022907,
    -4177443, -1107830, 2711467, 856792, -600566, -1775688, -1722170, -1736879,
    -3841965, 562113, 474508, 3448316, -503402, -206116, -2341478, -1103259,
    -2707289, 1661389, -3586383, -3352428, -507668, -675632, -336059, 713006,
    1127932, -25633, 2403473, -772335, -1047367, 4932304
};

START_TEST(test_pseudo_remainder)
{
    size_t i;
    sc_poly_mpz_t a, b, rem;
    sc_poly_mpz_init(&a, 513);
    sc_poly_mpz_init(&b, 512);
    sc_poly_mpz_init(&rem, 513);
    poly_si32_to_mpi(&b, 512, test_int_f);
    sc_poly_mpz_set_si(&a, 0, 1);
    sc_poly_mpz_set_si(&a, 512, 1);

    sc_poly_mpz_pseudo_remainder(&a, &b, &rem);

    for (i=0; i<sizeof(tv_rem)/sizeof(tv_rem[0]); i++) {
        ck_assert_int_eq(sc_mpz_get_si(rem.p + i), tv_rem[i]);
    }

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&rem);
}
END_TEST

START_TEST(test_resultant)
{
    const char tv[2048] = "5ccabedcb7632cac973de4cbdaeab67671f33ca04f2809f76ab30ab93271e53427b9db0662eaca8fd6e9e2ea551ca149d8a84acdd31ceb47947d6fb2d144a7c468d5c12cdae52b5bb2d32f246b8614b419b2cffb2c41b7b08a9b11dc6fa601b6103697b5fe1ca4570d5fab860723235045c558c8822a8f35a93133a8814834f639aaef45bfd79848a8517c1b446d3fb7456de6df9effbf3355bc2d84f4bd7210cda540b3c94f8067e9fdcd0ddafa602049c03ff9eb40c7cccfa137d7f567ee1fa40fe5ff86a7a70ecaf6f34c67a1e92609f9493238c608c3840d1a63835e66add77cef2e636e996cd332a1639263666585054de02fa73855a6d2e281c8e7e1bbc2d26f5c61d9c308f3997b451486b65c25535c7649617d5fc9d4ababc3ef20175433421eec542fb2a875ac092a7bf389d4f2d1f432080db2210b35fd08144fbcb1f3242a9c4e0e4fbbb69b9f027606d30c68e5b7c8ec74ceff9e07bd179811b9ec295e9654204f7af4aaa5ad460cfed6db791c6c6133b3d579c4f953e2735d3a706afbb77b91e057afeb4f12d459096f565faff1e69f04beb0f58da0ae69fda58310fe86118f23973373efa99c8d62b57b9cb376d2e43a360f65273ff1fa2b20a6cc2ff59ad60ca4d953ebac8a1c2dcb20b9eba5b1cd6eb148c58b2a1b106eafa09c62ad254f3ab322d325f4cb12bb2806df5005da9497d07c2b7d12534ce8b77558844eb8ffe7c454d431cf50e12133315854ff0f7cdac74410e710008eaebaddadccd0ada3bc447e193acda5f30b3669e2174018f7a78bad04386e8a50cb234be729cb5b0051015ad6483787c2298d8e58a5859493e558b9077bd6b5bf1b43d484d0f8e01cd8fbca2d70871d9add7a5b3d94844398f7ee30c132590c172ec45ccc95f72ec6985a6b06a2491e472f567a364ecff702fb812fbe10ee3869e50fa7a4090dd1f27a069848ab86a7471de241df229f5f81543f72d0f1ed3a34f71cee58a3e7d36ac9835d352d9d1db938b9eabae9915fb2d9ffddbf1ac65f8083c146dd4c78d912f72da6c0b4b5abfa4256b89a5f193d305f98b38d4dcd16e9e3e1efbda86fc7120fead976a7c39cbc358c1b20a96ce4f7fb8e2cc80c78c45a2f3e6f42a67d7461f15a53dd8e4a4e4d183e71d80818989f497151a7917396797e91229fb0625bc8a1f85bb15df3f9c572ea8b756fff6fb5c8c73f9c535705426defa1d6d36bd07f0f482e236ca222c3bd9b62fdca34c4bb1f181a21e13d190a86a129f5d039f018404d113da2fc01";
    char resultant[8192];
    SINT32 retval;
    sc_mpz_t gcd;
    sc_poly_mpz_t a, b;

    FILE *stream;
    stream = freopen("/dev/null", "a", stdout);
    ck_assert_ptr_ne(stream, NULL);
    setbuf(stdout, resultant);

    sc_mpz_init(&gcd);
    sc_poly_mpz_init(&a, 513);
    sc_poly_mpz_init(&b, 512);
    poly_si32_to_mpi(&b, 512, test_int_f);
    sc_poly_mpz_set_si(&a, 0, 1);
    sc_poly_mpz_set_si(&a, 512, 1);
    retval = sc_poly_mpz_resultant(&a, &b, &gcd);
    ck_assert_int_eq(retval, SC_FUNC_SUCCESS);
    mpz_out_str(stdout, 16, &gcd);
    ck_assert_int_eq(strncmp(tv, resultant, strlen(tv)), 0);
    sc_mpz_clear(&gcd);
    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
}
END_TEST

START_TEST(test_mul_karatsuba)
{
    size_t i;
    const size_t n = 3;
    const size_t m = 2*(2*(n+1)/2)-1;
    sc_poly_mpz_t a, b, out_karatsuba, out_gradeschool;
    sc_poly_mpz_init(&a, n);
    sc_poly_mpz_init(&b, n);
    sc_poly_mpz_init(&out_karatsuba, m);
    sc_poly_mpz_init(&out_gradeschool, m);
    poly_si32_to_mpi(&a, n, test_int_g);
    poly_si32_to_mpi(&b, n, test_int_f);

    sc_poly_mpz_mul_karatsuba(&out_karatsuba, &a, &b);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &a, &b);

    for (i=0; i<m; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_karatsuba.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&out_karatsuba);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_karatsuba_2)
{
    size_t i;
    const size_t n = 16;
    const size_t m = 2*(2*(n+1)/2)-1;
    sc_poly_mpz_t a, b, out_karatsuba, out_gradeschool;
    sc_poly_mpz_init(&a, n);
    sc_poly_mpz_init(&b, n);
    sc_poly_mpz_init(&out_karatsuba, m);
    sc_poly_mpz_init(&out_gradeschool, m);
    poly_si32_to_mpi(&a, n, test_int_g);
    poly_si32_to_mpi(&b, n, test_int_f);

    sc_poly_mpz_mul_karatsuba(&out_karatsuba, &a, &b);
    fprintf(stderr, "out Karatsuba = ");
    for (i=0; i<m; i++) {
        mpz_out_str(stderr, 16, out_karatsuba.p + i);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");

    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &a, &b);
    fprintf(stderr, "out Gradeschool = ");
    for (i=0; i<m; i++) {
        mpz_out_str(stderr, 16, out_gradeschool.p + i);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");

    for (i=0; i<m; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_karatsuba.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&out_karatsuba);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_karatsuba_3)
{
    size_t i;
    const size_t n = 67;
    const size_t m = 2*(2*(n+1)/2)-1;
    sc_poly_mpz_t a, b, out_karatsuba, out_gradeschool;
    sc_poly_mpz_init(&a, n);
    sc_poly_mpz_init(&b, n);
    sc_poly_mpz_init(&out_karatsuba, m);
    sc_poly_mpz_init(&out_gradeschool, m);
    poly_si32_to_mpi(&a, n, test_int_g);
    poly_si32_to_mpi(&b, n, test_int_f);

    sc_poly_mpz_mul_karatsuba(&out_karatsuba, &a, &b);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &a, &b);

    for (i=0; i<m; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_karatsuba.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&out_karatsuba);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_karatsuba_4)
{
    size_t i;
    const size_t n = 512;
    const size_t m = 2*(2*(n+1)/2)-1;
    sc_poly_mpz_t a, b, out_karatsuba, out_gradeschool;
    sc_poly_mpz_init(&a, n);
    sc_poly_mpz_init(&b, n);
    sc_poly_mpz_init(&out_karatsuba, m);
    sc_poly_mpz_init(&out_gradeschool, m);
    poly_si32_to_mpi(&a, n, test_int_g);
    poly_si32_to_mpi(&b, n, test_int_f);

    sc_poly_mpz_mul_karatsuba(&out_karatsuba, &a, &b);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &a, &b);

    for (i=0; i<m; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_karatsuba.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&a);
    sc_poly_mpz_clear(&b);
    sc_poly_mpz_clear(&out_karatsuba);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_pack_unpack)
{
    size_t i;
    const size_t n = 2*SC_LIMB_BITS;
    size_t num_words = 4*((n+SC_LIMB_BITS-1)/SC_LIMB_BITS);
    sc_ulimb_t out[num_words+1];
    sc_poly_mpz_t in, res;
    sc_poly_mpz_init(&in, 4);
    sc_poly_mpz_init(&res, 4);
    poly_si32_to_mpi(&in, 4, test_int_g);

    for (i=0; i<num_words+1; i++) {
        out[i] = 0;
    }

    sc_poly_mpz_ks_bit_pack(out, &in, 4, n, 0);
    sc_poly_mpz_ks_bit_unpack(&res, 4, out, n, 0);

    for (i=0; i<4; i++) {
        ck_assert_uint_eq(mpz_get_ui(in.p + i), mpz_get_ui(res.p + i));
    }

    sc_poly_mpz_clear(&in);
    sc_poly_mpz_clear(&res);
}
END_TEST

START_TEST(test_mul_pack_unpack_2)
{
    size_t i;
    const size_t n = 95;
    const size_t len = 256;
    size_t num_words = len*((n+SC_LIMB_BITS-1)/SC_LIMB_BITS);
    sc_ulimb_t out[num_words+1];
    sc_poly_mpz_t in, res;
    sc_poly_mpz_init(&in, len);
    sc_poly_mpz_init(&res, len);
    poly_si32_to_mpi(&in, len, test_int_g);

    for (i=0; i<num_words+1; i++) {
        out[i] = 0;
    }

    sc_poly_mpz_ks_bit_pack(out, &in, len, n, 0);
    sc_poly_mpz_ks_bit_unpack(&res, len, out, n, 0);

    for (i=0; i<len; i++) {
        ck_assert_uint_eq(mpz_get_ui(in.p + i), mpz_get_ui(res.p + i));
    }

    sc_poly_mpz_clear(&in);
    sc_poly_mpz_clear(&res);
}
END_TEST

START_TEST(test_mul_pack_unpack_3)
{
    size_t i;
    const size_t n = 95;
    const size_t len = 68;
    size_t num_words = len*((n+SC_LIMB_BITS-1)/SC_LIMB_BITS);
    sc_ulimb_t out[num_words+1];
    sc_poly_mpz_t in, res;
    sc_poly_mpz_init(&in, len);
    sc_poly_mpz_init(&res, len);
    poly_si32_to_mpi(&in, len, test_int_f);

    for (i=0; i<num_words+1; i++) {
        out[i] = 0;
    }

    sc_poly_mpz_ks_bit_pack(out, &in, len, n, 0);
    sc_poly_mpz_ks_bit_unpack(&res, len, out, n, 0);

    for (i=0; i<len; i++) {
        ck_assert_uint_eq(mpz_get_ui(in.p + i), mpz_get_ui(res.p + i));
    }

    sc_poly_mpz_clear(&in);
    sc_poly_mpz_clear(&res);
}
END_TEST

START_TEST(test_mul_kronecker)
{
    size_t i;
    const size_t len = 8;

    sc_poly_mpz_t in1, in2, out_kronecker, out_gradeschool;
    sc_poly_mpz_init(&in1, len);
    sc_poly_mpz_init(&in2, len);
    sc_poly_mpz_init(&out_kronecker, 2*len-1);
    sc_poly_mpz_init(&out_gradeschool, 2*len-1);

    poly_si32_to_mpi(&in1, len, test_int_f);
    poly_si32_to_mpi(&in2, len, test_int_g);

    sc_poly_mpz_mul_kronecker(&out_kronecker, &in1, &in2);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &in1, &in2);

    for (i=0; i<2*len-1; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_kronecker.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&in1);
    sc_poly_mpz_clear(&in2);
    sc_poly_mpz_clear(&out_kronecker);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_kronecker_2)
{
    size_t i;
    const size_t len = 68;

    sc_poly_mpz_t in1, in2, out_kronecker, out_gradeschool;
    sc_poly_mpz_init(&in1, len);
    sc_poly_mpz_init(&in2, len);
    sc_poly_mpz_init(&out_kronecker, 2*len-1);
    sc_poly_mpz_init(&out_gradeschool, 2*len-1);

    poly_si32_to_mpi(&in1, len, test_int_f);
    poly_si32_to_mpi(&in2, len, test_int_g);

    sc_poly_mpz_mul_kronecker(&out_kronecker, &in1, &in2);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &in1, &in2);

    for (i=0; i<2*len-1; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_kronecker.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&in1);
    sc_poly_mpz_clear(&in2);
    sc_poly_mpz_clear(&out_kronecker);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

START_TEST(test_mul_kronecker_3)
{
    size_t i;
    const size_t len = 512;

    sc_poly_mpz_t in1, in2, out_kronecker, out_gradeschool;
    sc_poly_mpz_init(&in1, len);
    sc_poly_mpz_init(&in2, len);
    sc_poly_mpz_init(&out_kronecker, 2*len-1);
    sc_poly_mpz_init(&out_gradeschool, 2*len-1);

    poly_si32_to_mpi(&in1, len, test_int_f);
    poly_si32_to_mpi(&in2, len, test_int_g);

    sc_poly_mpz_mul_kronecker(&out_kronecker, &in1, &in2);
    sc_poly_mpz_mul_gradeschool(&out_gradeschool, &in1, &in2);

    /*fprintf(stderr, "out Kronecker = ");
    for (i=0; i<2*len-1; i++) {
        mpz_out_str(stderr, 10, out_kronecker.p + i);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "out Gradeschool = ");
    for (i=0; i<2*len-1; i++) {
        mpz_out_str(stderr, 10, out_gradeschool.p + i);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");*/

    for (i=0; i<2*len-1; i++) {
        ck_assert_uint_eq(mpz_get_ui(out_kronecker.p + i),
            mpz_get_ui(out_gradeschool.p + i));
    }

    sc_poly_mpz_clear(&in1);
    sc_poly_mpz_clear(&in2);
    sc_poly_mpz_clear(&out_kronecker);
    sc_poly_mpz_clear(&out_gradeschool);
}
END_TEST

Suite *poly_mpi_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("poly_mpi");

    /* Test cases */
    tc_core = tcase_create("CORE");
    tcase_set_timeout(tc_core, 10.0f);
    tcase_add_test(tc_core, test_degree);
    tcase_add_test(tc_core, test_div_0);
    tcase_add_test(tc_core, test_div_1);
    tcase_add_test(tc_core, test_div_2);
    tcase_add_test(tc_core, test_div_3);
    tcase_add_test(tc_core, test_xgcd_0);
    tcase_add_test(tc_core, test_xgcd_1);
    tcase_add_test(tc_core, test_xgcd_2);
    tcase_add_test(tc_core, test_content);
    tcase_add_test(tc_core, test_content_scale);
    tcase_add_test(tc_core, test_pseudo_remainder);
    tcase_add_test(tc_core, test_resultant);
    tcase_add_test(tc_core, test_mul_karatsuba);
    tcase_add_test(tc_core, test_mul_karatsuba_2);
    tcase_add_test(tc_core, test_mul_karatsuba_3);
    tcase_add_test(tc_core, test_mul_karatsuba_4);
    tcase_add_test(tc_core, test_mul_pack_unpack);
    tcase_add_test(tc_core, test_mul_pack_unpack_2);
    tcase_add_test(tc_core, test_mul_pack_unpack_3);
    tcase_add_test(tc_core, test_mul_kronecker);
    tcase_add_test(tc_core, test_mul_kronecker_2);
    tcase_add_test(tc_core, test_mul_kronecker_3);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = poly_mpi_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


