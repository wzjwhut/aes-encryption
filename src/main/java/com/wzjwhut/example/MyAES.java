package com.wzjwhut.example;

import com.wzjwhut.util.HexUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/** 一个简单的用于演示RSA过程 */
public class MyAES {
    private final static Logger logger = LogManager.getLogger(MyAES.class);

    public static final String SBOX =
            "63\t7c\t77\t7b\tf2\t6b\t6f\tc5\t30\t01\t67\t2b\tfe\td7\tab\t76\n" +
            "ca\t82\tc9\t7d\tfa\t59\t47\tf0\tad\td4\ta2\taf\t9c\ta4\t72\tc0\n" +
            "b7\tfd\t93\t26\t36\t3f\tf7\tcc\t34\ta5\te5\tf1\t71\td8\t31\t15\n" +
            "04\tc7\t23\tc3\t18\t96\t05\t9a\t07\t12\t80\te2\teb\t27\tb2\t75\n" +
            "09\t83\t2c\t1a\t1b\t6e\t5a\ta0\t52\t3b\td6\tb3\t29\te3\t2f\t84\n" +
            "53\td1\t00\ted\t20\tfc\tb1\t5b\t6a\tcb\tbe\t39\t4a\t4c\t58\tcf\n" +
            "d0\tef\taa\tfb\t43\t4d\t33\t85\t45\tf9\t02\t7f\t50\t3c\t9f\ta8\n" +
            "51\ta3\t40\t8f\t92\t9d\t38\tf5\tbc\tb6\tda\t21\t10\tff\tf3\td2\n" +
            "cd\t0c\t13\tec\t5f\t97\t44\t17\tc4\ta7\t7e\t3d\t64\t5d\t19\t73\n" +
            "60\t81\t4f\tdc\t22\t2a\t90\t88\t46\tee\tb8\t14\tde\t5e\t0b\tdb\n" +
            "e0\t32\t3a\t0a\t49\t06\t24\t5c\tc2\td3\tac\t62\t91\t95\te4\t79\n" +
            "e7\tc8\t37\t6d\t8d\td5\t4e\ta9\t6c\t56\tf4\tea\t65\t7a\tae\t08\n" +
            "ba\t78\t25\t2e\t1c\ta6\tb4\tc6\te8\tdd\t74\t1f\t4b\tbd\t8b\t8a\n" +
            "70\t3e\tb5\t66\t48\t03\tf6\t0e\t61\t35\t57\tb9\t86\tc1\t1d\t9e\n" +
            "e1\tf8\t98\t11\t69\td9\t8e\t94\t9b\t1e\t87\te9\tce\t55\t28\tdf\n" +
            "8c\ta1\t89\t0d\tbf\te6\t42\t68\t41\t99\t2d\t0f\tb0\t54\tbb\t16";

    private static int[][] sbox = new int[16][16];

    static{
        String[] rows = StringUtils.split(SBOX, '\n');
        for(int i=0; i<16; i++){
            String[] cols = StringUtils.split(rows[i], '\t');
            //logger.info("row: {}", rows[i]);
            for(int j=0; j<16; j++){
                //logger.info("col: {}", cols[j]);
                sbox[i][j] = Integer.parseInt(cols[j], 16);
            }
        }
        logger.info("sbox\r\n{}", HexUtils.dumpByteTable(sbox));
    }

    final int NR = 10;
    public MyAES(){

    }


    public byte[] encrypt(byte[] key, byte[] input){
        if(input.length > 16 || key.length > 16){
            throw new RuntimeException("暂不支持超过16字节的数据");
        }
        key = Arrays.copyOf(key, 16);
        input = Arrays.copyOf(input, 16);

        logger.info("input\r\n{}", HexUtils.dumpString(input, 16));
        logger.info("key\r\n{}", HexUtils.dumpString(key, 16));

        final int[][] s = new int[4][4];
        /** 为了方便代码编程, 一个w存一行, 总共有4*(NR+1)行 */
        final int[][] W  = new int[4*(NR+1)][4];
        int index;

        /** 1. 初始化state, 用输入的数据装入state, 从上到下, 从左到右 */
        index = 0;
        for(int col=0; col<4; col++){
            for(int row=0; row<4; row++){
                s[row][col] = input[index++]&0xff;
            }
        }
        logger.info("state\r\n{}", HexUtils.dumpByteTable(s));

        /** 2. 生成w0, w1, w2, w3 */
        index = 0;
        for(int row=0; row<4; row++){
            for(int col=0; col<4; col++){
                W[row][col] = key[index++]&0xff;
            }
        }
        logger.info("w\r\n{}", HexUtils.dumpByteTable(W));
        /** 生成所有的w */
        keySchedule(W);
        logger.info("w\r\n{}", HexUtils.dumpByteTable(W));

        /** addRoundKey(s, w),  即s按列与w异或*/
        int[][] tempW = new int[4][4];
        addRoundKey(s, getw(W, 0, tempW));
        logger.info("s\r\n{}", HexUtils.dumpByteTable(s));
        for(int i=1;  i<=NR-1; i++){
            subBytes(s, s);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, getw(W, i, tempW));
        }

        subBytes(s, s);
        logger.info("subBytes\r\n{}", HexUtils.dumpByteTable(s));
        shiftRows(s);
        logger.info("shiftRows\r\n{}", HexUtils.dumpByteTable(s));
        addRoundKey(s, getw(W, NR, tempW));
        logger.info("addRoundKey\r\n{}", HexUtils.dumpByteTable(s));
        byte[] cipherText = new byte[16];
        index = 0;
        for(int col=0; col<4; col++){
        for(int row=0; row<4; row++){

                cipherText[index++] = (byte) (s[row][col]);
            }
        }
        return cipherText;
    }


    private int[][] getw(int[][] W, int i, int[][] out){
        int index =  i*4;
        int[][] in = new int[][]{W[index], W[index+1], W[index+2], W[index+3]};
//        for(int row=0; row<4; row++){
//            for(int col=0; col<4; col++){
//                out[row][col] = W[srcRow + col][row];
//            }
//        }
        return matrixT(in, out);
    }

    public static int[][] matrixT(int[][] in, int[][] out){
        int maxRows = in.length;
        int maxCols = in[0].length;
        if(out == null){
            out = new int[maxRows][maxCols];
        }
        for(int row=0; row<maxRows; row++){
            for(int col=0; col<maxCols; col++){
                out[row][col] = in[col][row];
            }
        }
        return out;
    }


    private void keySchedule(int[][] W){
        final int Nk = 4;
        final int[] R = new int[]{0, 0, 0, 0};
        final int[] temp = new int[4];
        for(int j=Nk; j<=(4*(NR+1)-1); j++){
            int[] Wj = W[j];
            int[] Wj_nk = W[j-Nk];
            int[] Wj_1 = W[j-1];
            if(j%Nk == 0){
                //R[0] = 1<<( (j/Nk)-1);
                R[0] = rcon(j/Nk);
                xor(Wj_nk, subBytes(shiftColumn(Wj_1, temp)), Wj);
                xor(Wj, R, Wj);
            }else{
                xor(Wj_nk, Wj_1, Wj);
            }
        }
    }

    private int[] shiftColumn(int[] w, int[] out){
        out[0] = w[1];
        out[1] = w[2];
        out[2] = w[3];
        out[3] = w[0];
        return out;
    }

    public static int[][] subBytes(int[][] s, int[][] out){
        int maxRows = s.length;
        int maxCols = s[0].length;
        if(out == null){
            out = new int[maxRows][maxCols];
        }
        for(int row=0; row<maxRows; row++){
            for(int col=0; col<maxCols; col++){
                int value = s[row][col];
                int r = (value>>4) & 0x0f;
                int c = (value)&0x0f;
                out[row][col] = sbox[r][c];
            }
        }
        return out;
    }

    private void xor(int[] a, int[] b, int[] out){
        for(int i=0; i<a.length; i++){
            out[i] = a[i]^b[i];
        }
    }

    public static int[] subBytes(int[] col){
        for(int i=0; i<col.length; i++){
            int value = col[i];
            int r = (value>>4) & 0x0f;
            int c = (value)&0x0f;
            col[i] = sbox[r][c];
        }
        return col;
    }

    public static void addRoundKey(int[][] s, int[][] w){
        logger.info("addRoundKey w\r\n{}", HexUtils.dumpByteTable(w));
        for(int i=0; i<s.length; i++){
            int[] row = s[i];
            for(int j=0; j<row.length; j++){
                //logger.info("addRoundKey: {}^{}", s[i][j], w[i][j]);
                s[i][j] = s[i][j]^w[i][j];
            }
        }
        logger.info("addRoundKey s\r\n{}", HexUtils.dumpByteTable(s));
    }

    public static void shiftRows(int[][] s){
        int[][] temp = new int[4][4];
        for(int r=0; r<4; r++){
            for(int c=0; c<4; c++){
                temp[r][c] = s[r][(c+r)%4];
            }
        }
        copyTo(temp, s);
    }

    public static void copyTo(int[][] from, int[][] to){
        for(int i=0; i<from.length; i++){
            int[] row = from[i];
            for(int j=0; j<row.length; j++){
                to[i][j] = from[i][j];
            }
        }
    }

    public static void mixColumns(int[][] s){
        int[][] temp = new int[4][4];
        for(int c=0; c<4; c++){
            temp[0][c] = ( GF256Multiplication(2, s[0][c]))^( GF256Multiplication(3, s[1][c]))^s[2][c]^s[3][c];
            temp[1][c] = s[0][c]^( GF256Multiplication(2, s[1][c]))^( GF256Multiplication(3, s[2][c]))^s[3][c];
            temp[2][c] = s[0][c]^s[1][c]^( GF256Multiplication(2, s[2][c]))^( GF256Multiplication(3, s[3][c]));
            temp[3][c] = ( GF256Multiplication(3, s[0][c]))^s[1][c]^s[2][c]^( GF256Multiplication(2, s[3][c]));
        }
        copyTo(temp, s);
    }

    public static int GF256Multiplication(int a, int b){
        /** GF256乘法运算, 参考方法https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field */
        int p = 0; /* the product of the multiplication */
        while (a!=0 && b!=0) {
            if ((b & 1) != 0) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
                p ^= a; /* since we're in GF(2^m), addition is an XOR */

            if ((a & 0x80)!=0) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
                a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
            else
                a <<= 1; /* equivalent to a*2 */
            b >>= 1; /* equivalent to b // 2 */
        }
        return p;
    }

    public static int rcon(int i){
        if(i==1){
            return 1;
        }
        int rcon_1 = rcon(i-1);
        if(i>1 && rcon_1< 0x80){
            return (2 * rcon(i-1));
        }else if(i>1 && rcon_1 >= 0x80){
            return ((2 * rcon(i-1))^0x11B);
        }else{
            logger.error("invalid i: {}", i);
            return 0;
        }
    }


}
