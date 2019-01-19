package com.wzjwhut.example;

import com.wzjwhut.util.HexUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Base64;

public class Main {
    private final static Logger logger = LogManager.getLogger(Main.class);

    private final static byte[] rawMessage = "hello world".getBytes();

    public static void main(String[] args) throws Exception {
        byte[][] sbox = new byte[16][16];
        sbox[1][1] = 11;

        int[][] matrix = new int[][]{
                new int[]{0, 1, 2, 4},
                new int[]{0, 1, 2, 4},
                new int[]{0, 1, 2, 4},
                new int[]{0, 1, 2, 4},
        };
        logger.info("src \r\n{}", HexUtils.dumpByteTable(matrix));
        logger.info("matrix T\r\n{}", HexUtils.dumpByteTable(MyAES.matrixT(matrix, null)));
        logger.info("sub\r\n{}", HexUtils.dumpByteTable(MyAES.subBytes(matrix, null)));

        logger.info("{}, {}, {}, {}", Integer.toHexString(MyAES.rcon(1)), Integer.toHexString(MyAES.rcon(3)),
                Integer.toHexString(MyAES.rcon(3)),
                        Integer.toHexString(MyAES.rcon(10)));

        /** https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=51031 */
        /**
            打开在线加密http://tool.chacuo.net/cryptaes,
            选择ECB, 填充选择 zeropadding.
         原文为 hello world
         密码为 123456
         结果为 kb5XlmwEaZkcNlmGmePwwg==

         */
        byte[] plain = new String("hello world").getBytes();
        byte[] key = new String("123456").getBytes();
        String base64Out = Base64.getEncoder().encodeToString(new MyAES().encrypt(key, plain));
        logger.info("my aes out: {}", base64Out);
        byte[] c = SystemAES.encrypt(key, plain);
        logger.info("system aes encode out: {}", Base64.getEncoder().encodeToString(c));
        logger.info("system aes decode out: {}", new String(SystemAES.decrypt(key, c)));
        if(!base64Out.equals("kb5XlmwEaZkcNlmGmePwwg==")){
            logger.error("encrypted failed");
        }else{
            logger.error("encrypted successfully");
        }
        LogManager.shutdown();
    }
}
