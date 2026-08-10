/*
 * Decompiler-style reconstruction corresponding to score_bytes.o.
 * Generic names and explicit casts intentionally resemble normalized output.
 */
typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long ulong;

int score_bytes(byte *param_1, ulong param_2, int param_3) {
    byte bVar1;
    byte bVar2;
    uint uVar3;
    ulong uVar4;
    int iVar5;

    if ((param_1 == (byte *)0) || (param_2 == 0)) {
        return -1;
    }

    uVar3 = (uint)param_3 ^ 0x9e3779b9u;
    bVar1 = *param_1;
    uVar4 = 0;
    iVar5 = 0;

    do {
        bVar2 = param_1[uVar4];
        if (bVar2 != bVar1) {
            iVar5 = iVar5 + 1;
        }

        switch (uVar4 & 3) {
            case 0:
                uVar3 = uVar3 + (uint)bVar2 * 3u;
                break;
            case 1:
                uVar3 = uVar3 ^ (uint)bVar2 << 5;
                break;
            case 2:
                uVar3 = (uVar3 << 7 | uVar3 >> 25) + (uint)bVar2;
                break;
            default:
                uVar3 = uVar3 - (uint)bVar2 * 7u;
                break;
        }

        bVar1 = bVar2;
        uVar4 = uVar4 + 1;
    } while (uVar4 < param_2);

    return (int)((uVar3 ^ (uint)iVar5) & 0x7fffffffu);
}
