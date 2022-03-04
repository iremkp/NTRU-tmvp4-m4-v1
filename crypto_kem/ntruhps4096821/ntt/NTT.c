#include "NTT.h"


const int root_table[567] = {501252, 501252, 813816, 501252, 813816, -528216, 375962, -980652, 1176926, -1481904, 421223, -747718, -980652, -363110, -1481904, -980652, -363110, 1176926, -1481904, 797185, -219502, 1033921, 1646113, 1619741, -84156, 301356, -618416, -1587783, -553862, -19276, -368167, 1033921, 1215190, 1577955, -782383, -1587783, 1277946, 1639017, 1083739, 1662111, -553862, -1531963, -19276, 1033921, 1215190, 1646113, 1619741, -282596, -653314, 1619741, -618416, -1587783, 784091, 1184556, 1277946, 1639017, 1639017, -553862, -1531963, -19276, -368167, 130777, 1467152, 501252, 501252, 813816, 501252, 813816, -528216, 375962, 813816, -528216, 375962, 1019169, -92513, 1377729, -1211401, -528216, 1019169, -92513, -1466880, -1279676, 1225515, 574218, 375962, 1377729, -1211401, -610895, -1524973, -407384, 194742, 1019169, -1466880, -1279676, 1314995, 134301, -696682, -227254, -92513, 1225515, 574218, -1252902, -1385566, -160209, 196491, 1377729, -610895, -1524973, -1037090, -286265, -1145973, -1077888, -1211401, -407384, 194742, 218297, 1589023, -341068, 542273, 807143, -1014046, -352467, -374813, -534730, 80181, 872327, -1397813, 822206, 116095, -950968, 1170427, 1317885, -968790, 1599952, -823617, 679840, 688607, 240813, -698819, -789248, 1573882, 1677992, 1459514, 925197, 1318979, 1272184, 708000, 1176926, 421223, -747718, 807143, -1397813, 1599952, 1573882, -1481904, -980652, -363110, 1176926, -1481904, 797185, -219502, 797185, -186412, 570586, -523479, 1016948, 826550, 258428, -219502, -772518, 1673104, 626379, -220697, -249399, -545675, 421223, 807143, -1397813, -1014046, -352467, 822206, 116095, -747718, 1599952, 1573882, -823617, 679840, 1677992, 1459514, -980652, 1176926, -1481904, 421223, -747718, -980652, -363110, -363110, 797185, -219502, -186412, 570586, -772518, 1673104, -186412, -523479, 1016948, -271138, -750493, 628154, 609900, 570586, 826550, 258428, 543158, -771160, -164763, -366446, -772518, 626379, -220697, 1499438, 11318, -731595, -790896, 1673104, -249399, -545675, 44322, -848816, 1323419, -686747, 1338610, 434762, 502421, 729568, 128688, 177906, -41986, 955317, -652247, -16366, -341159, 135640, 541523, -199498, 1150118, -1342747, 1528605, -777153, 82502, -1078832, -1481962, -556632, -99774, -400966, -1515223, 907115, -1040870, -1125999, 784091, -723768, -211365, 1118585, 1001757, 314240, 1625063, 1184556, 1123664, -749365, -55196, -993470, 658023, 751052, 1277946, 1083739, 1662111, 73816, -977947, -425374, 62402, 1639017, -553862, -1531963, -19276, -368167, 130777, 1467152, 1646113, -84156, 301356, 1338610, 955317, 1150118, -556632, 1619741, -618416, -1587783, 784091, 1184556, 1277946, 1639017, -282596, -1420619, -712999, -1254450, -831972, 327996, 1514856, -653314, 274199, -1548652, 1170889, 1203183, 724828, -1672216, 892915, 468897, 918159, 735458, 1187861, 629267, 146646, 1601585, 537925, -225966, 645052, -771787, -405243, 1181437, -482816, -744166, -230463, 435621, 1677990, 544388, 249991, 1237504, -935449, 616714, -176676, 1063137, -1651504, 660393, 73816, 130689, -1145132, -362727, -1265232, -561580, -1476491, -977947, 911891, 407298, -169542, -418439, 285984, 259178, -425374, 728387, 103163, -363257, 1359343, -42219, -516364, 62402, 452531, 1570406, 1387359, -193935, -194513, -493627, -19276, 1033921, 1215190, 1646113, 1619741, -282596, -653314, -368167, 1577955, -782383, 892915, 1601585, -482816, 1237504, 130777, 1337287, 997967, -900235, -1357976, -1043801, -169132, 1467152, 1195585, 1528906, -1583024, -1453096, 1459660, -1321466, -84156, 1338610, 955317, 434762, 502421, -652247, -16366, 301356, 1150118, -556632, -1342747, 1528605, -99774, -400966, -618416, 784091, 1184556, -723768, -211365, 1123664, -749365, -1587783, 1277946, 1639017, 1083739, 1662111, -553862, -1531963, -1420619, -1254450, -831972, -244051, -1501599, 1536500, -954512, -712999, 327996, 1514856, -1408592, 1547474, -1268616, 1181564, 274199, 1170889, 1203183, 13062, -1436097, 459273, -1145040, -1548652, 724828, -1672216, -91681, -186155, -769374, -1068810, -723768, 1118585, 1001757, 1273680, 1364431, -248593, -790433, -211365, 314240, 1625063, 1523256, -331681, -690303, 1426689, 1123664, -55196, -993470, -1081518, 1087466, 1673163, 1147112, -749365, 658023, 751052, -1431183, -1613863, 1570856, -1474419, 1083739, 73816, -977947, 130689, -1145132, 911891, 407298, 1662111, -425374, 62402, 728387, 103163, 452531, 1570406, -553862, -19276, -368167, 1033921, 1215190, 1577955, -782383, -1531963, 130777, 1467152, 1337287, 997967, 1195585, 1528906, 1033921, 1646113, 1619741, -84156, 301356, -618416, -1587783, 1215190, -282596, -653314, -1420619, -712999, 274199, -1548652, 1577955, 892915, 1601585, 468897, 918159, 537925, -225966, -782383, -482816, 1237504, -744166, -230463, -935449, 616714, 1337287, -900235, -1357976, -504148, 1335008, 737129, 1072939, 997967, -1043801, -169132, -856098, -814407, -777371, -1187504, 1195585, -1583024, -1453096, -840201, 62081, 1507655, -70416, 1528906, 1459660, -1321466, -94098, -187098, -261480, -125689};
const int inv_root_table[567] = {501252, 501252, -813816, 501252, -813816, -375962, 528216, -813816, -375962, 528216, 1211401, -1377729, 92513, -1019169, -375962, 1211401, -1377729, -194742, 407384, 1524973, 610895, 528216, 92513, -1019169, -574218, -1225515, 1279676, 1466880, 1211401, -194742, 407384, -542273, 341068, -1589023, -218297, -1377729, 1524973, 610895, 1077888, 1145973, 286265, 1037090, 92513, -574218, -1225515, -196491, 160209, 1385566, 1252902, -1019169, 1279676, 1466880, 227254, 696682, -134301, -1314995, -1673104, 545675, 249399, 686747, -1323419, 848816, -44322, 772518, 220697, -626379, 790896, 731595, -11318, -1499438, -570586, -258428, -826550, 366446, 164763, 771160, -543158, 186412, -1016948, 523479, -609900, -628154, 750493, 271138, 363110, 219502, -797185, -1673104, 772518, -570586, 186412, 980652, 1481904, -1176926, 363110, 980652, 747718, -421223, 747718, -1573882, -1599952, -1459514, -1677992, -679840, 823617, -421223, 1397813, -807143, -116095, -822206, 352467, 1014046, 219502, -1673104, 772518, 545675, 249399, 220697, -626379, -797185, -570586, 186412, -258428, -826550, -1016948, 523479, 1481904, 363110, 980652, 219502, -797185, 1481904, -1176926, -1176926, 747718, -421223, -1573882, -1599952, 1397813, -807143, -1573882, -1459514, -1677992, -708000, -1272184, -1318979, -925197, -1599952, -679840, 823617, 789248, 698819, -240813, -688607, 1397813, -116095, -822206, 968790, -1317885, -1170427, 950968, -807143, 352467, 1014046, -872327, -80181, 534730, 374813, -1528906, 1321466, -1459660, 125689, 261480, 187098, 94098, -1195585, 1453096, 1583024, 70416, -1507655, -62081, 840201, -997967, 169132, 1043801, 1187504, 777371, 814407, 856098, -1337287, 1357976, 900235, -1072939, -737129, -1335008, 504148, 782383, -1237504, 482816, -616714, 935449, 230463, 744166, -1577955, -1601585, -892915, 225966, -537925, -918159, -468897, -1215190, 653314, 282596, 1548652, -274199, 712999, 1420619, -1033921, -1619741, -1646113, 1587783, 618416, -301356, 84156, 1531963, -1467152, -130777, -1528906, -1195585, -997967, -1337287, 553862, 368167, 19276, 782383, -1577955, -1215190, -1033921, -1662111, -62402, 425374, -1570406, -452531, -103163, -728387, -1083739, 977947, -73816, -407298, -911891, 1145132, -130689, 749365, -751052, -658023, 1474419, -1570856, 1613863, 1431183, -1123664, 993470, 55196, -1147112, -1673163, -1087466, 1081518, 211365, -1625063, -314240, -1426689, 690303, 331681, -1523256, 723768, -1001757, -1118585, 790433, 248593, -1364431, -1273680, 1548652, 1672216, -724828, 1068810, 769374, 186155, 91681, -274199, -1203183, -1170889, 1145040, -459273, 1436097, -13062, 712999, -1514856, -327996, -1181564, 1268616, -1547474, 1408592, 1420619, 831972, 1254450, 954512, -1536500, 1501599, 244051, 1587783, -1639017, -1277946, 1531963, 553862, -1662111, -1083739, 618416, -1184556, -784091, 749365, -1123664, 211365, 723768, -301356, 556632, -1150118, 400966, 99774, -1528605, 1342747, 84156, -955317, -1338610, 16366, 652247, -502421, -434762, -1467152, -1528906, -1195585, 1321466, -1459660, 1453096, 1583024, -130777, -997967, -1337287, 169132, 1043801, 1357976, 900235, 368167, 782383, -1577955, -1237504, 482816, -1601585, -892915, 19276, -1215190, -1033921, 653314, 282596, -1619741, -1646113, -62402, -1570406, -452531, 493627, 194513, 193935, -1387359, 425374, -103163, -728387, 516364, 42219, -1359343, 363257, 977947, -407298, -911891, -259178, -285984, 418439, 169542, -73816, 1145132, -130689, 1476491, 561580, 1265232, 362727, -1237504, -616714, 935449, -660393, 1651504, -1063137, 176676, 482816, 230463, 744166, -249991, -544388, -1677990, -435621, -1601585, 225966, -537925, -1181437, 405243, 771787, -645052, -892915, -918159, -468897, -146646, -629267, -1187861, -735458, 653314, 1548652, -274199, 1672216, -724828, -1203183, -1170889, 282596, 712999, 1420619, -1514856, -327996, 831972, 1254450, -1619741, 1587783, 618416, -1639017, -1277946, -1184556, -784091, -1646113, -301356, 84156, 556632, -1150118, -955317, -1338610, -1639017, 1531963, 553862, -1467152, -130777, 368167, 19276, -1277946, -1662111, -1083739, -62402, 425374, 977947, -73816, -1184556, 749365, -1123664, -751052, -658023, 993470, 55196, -784091, 211365, 723768, -1625063, -314240, -1001757, -1118585, 556632, 400966, 99774, 1125999, 1040870, -907115, 1515223, -1150118, -1528605, 1342747, 1481962, 1078832, -82502, 777153, -955317, 16366, 652247, 199498, -541523, -135640, 341159, -1338610, -502421, -434762, 41986, -177906, -128688, -729568, 501252, 501252, -813816, 501252, -813816, -375962, 528216, 1481904, 363110, 980652, 219502, -797185, 1481904, -1176926, 980652, 1481904, -1176926, 363110, 980652, 747718, -421223, -1639017, 1531963, 553862, -1467152, -130777, 368167, 19276, -1619741, 1587783, 618416, -1639017, -1277946, -1184556, -784091, 19276, -1215190, -1033921, 653314, 282596, -1619741, -1646113, 1587783, -1639017, -1277946, 1531963, 553862, -1662111, -1083739, 553862, 368167, 19276, 782383, -1577955, -1215190, -1033921, -1033921, -1619741, -1646113, 1587783, 618416, -301356, 84156};
const int mul_table[288] = {501252, 813816, -528216, 375962, 1019169, -92513, 1377729, -1211401, -1466880, -1279676, 1225515, 574218, -610895, -1524973, -407384, 194742, 1314995, 134301, -696682, -227254, -1252902, -1385566, -160209, 196491, -1037090, -286265, -1145973, -1077888, 218297, 1589023, -341068, 542273, -374813, -534730, 80181, 872327, -950968, 1170427, 1317885, -968790, 688607, 240813, -698819, -789248, 925197, 1318979, 1272184, 708000, 807143, -1397813, 1599952, 1573882, 1176926, -1481904, 797185, -219502, -523479, 1016948, 826550, 258428, 626379, -220697, -249399, -545675, -1014046, -352467, 822206, 116095, -823617, 679840, 1677992, 1459514, 421223, -747718, -980652, -363110, -186412, 570586, -772518, 1673104, -271138, -750493, 628154, 609900, 543158, -771160, -164763, -366446, 1499438, 11318, -731595, -790896, 44322, -848816, 1323419, -686747, 729568, 128688, 177906, -41986, -341159, 135640, 541523, -199498, -777153, 82502, -1078832, -1481962, -1515223, 907115, -1040870, -1125999, 1118585, 1001757, 314240, 1625063, -55196, -993470, 658023, 751052, 73816, -977947, -425374, 62402, -19276, -368167, 130777, 1467152, 1338610, 955317, 1150118, -556632, 784091, 1184556, 1277946, 1639017, -1254450, -831972, 327996, 1514856, 1170889, 1203183, 724828, -1672216, 735458, 1187861, 629267, 146646, 645052, -771787, -405243, 1181437, 435621, 1677990, 544388, 249991, -176676, 1063137, -1651504, 660393, -362727, -1265232, -561580, -1476491, -169542, -418439, 285984, 259178, -363257, 1359343, -42219, -516364, 1387359, -193935, -194513, -493627, 1646113, 1619741, -282596, -653314, 892915, 1601585, -482816, 1237504, -900235, -1357976, -1043801, -169132, -1583024, -1453096, 1459660, -1321466, 434762, 502421, -652247, -16366, -1342747, 1528605, -99774, -400966, -723768, -211365, 1123664, -749365, 1083739, 1662111, -553862, -1531963, -244051, -1501599, 1536500, -954512, -1408592, 1547474, -1268616, 1181564, 13062, -1436097, 459273, -1145040, -91681, -186155, -769374, -1068810, 1273680, 1364431, -248593, -790433, 1523256, -331681, -690303, 1426689, -1081518, 1087466, 1673163, 1147112, -1431183, -1613863, 1570856, -1474419, 130689, -1145132, 911891, 407298, 728387, 103163, 452531, 1570406, 1033921, 1215190, 1577955, -782383, 1337287, 997967, 1195585, 1528906, -84156, 301356, -618416, -1587783, -1420619, -712999, 274199, -1548652, 468897, 918159, 537925, -225966, -744166, -230463, -935449, 616714, -504148, 1335008, 737129, 1072939, -856098, -814407, -777371, -1187504, -840201, 62081, 1507655, -70416, -94098, -187098, -261480, -125689};


extern void NTT_9_forward_16(const uint16_t *big_coeffs, int *_NTT_array1);
extern void NTT_9_forward_small(const uint16_t *small_coeffs, int *_NTT_array2);
extern void __asm_forward_NTT_6layers(int *NTT_array, int _MOD, int _Mprime, const int *_root_table);
extern void __asm_mul3x3(int *_NTT_array1, int *_NTT_array2, int _MOD, int _Mprime, const int *_root_table);
extern void __asm_inv_NTT_6layers(int *_NTT_array1, int _MOD, int _Mprime, const int *_inv_root_table);
extern void NTT_9_inv(int *_NTT_array1);
extern void final_pack(int *_NTT_array1, uint16_t *res_coeffs);
void mixed_radix_NTT_mul_864(uint16_t *res_coeffs, const uint16_t *small_coeffs, const uint16_t *big_coeffs){
    static int NTT_array1[9 * 192];
    static int NTT_array2[9 * 192];

    NTT_9_forward_16(big_coeffs, &NTT_array1[0]);
    NTT_9_forward_small(small_coeffs, &NTT_array2[0]);
    __asm_forward_NTT_6layers(&NTT_array1[0], MOD, Mprime, root_table);
    __asm_forward_NTT_6layers(&NTT_array2[0], MOD, Mprime, root_table);
    __asm_mul3x3(&NTT_array1[0], &NTT_array2[0], MOD, Mprime, mul_table);
    __asm_inv_NTT_6layers(&NTT_array1[0], MOD, Mprime, inv_root_table);
    NTT_9_inv(&NTT_array1[0]);
    final_pack(&NTT_array1[0], res_coeffs);
}