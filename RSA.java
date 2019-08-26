import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;


public class RSA {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = new BigInteger("2");
    private static final BigInteger THREE = new BigInteger("3");
    private final BigInteger publicKey;
    private final BigInteger privateKey;
    public MyBlocks mb;
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private static int blockSize = 250; //default value
    //private BigInteger temp;

    int d = 0;
    private int length;

    public RSA() {
        // generate 2 random primes of approx 1024 bits
        Random r = new Random();
        p = BigInteger.probablePrime(randomIntBetween(1800, 2000), r);
        q = BigInteger.probablePrime(randomIntBetween(1800, 2000), r);
        while (p.equals(q)) {
        // if p and q are equal , q should generate another random prime number
            q = randomBigIntBetween(512, 1024);
        }
        System.out.println("Value of  p : " + p);
        System.out.println("Value of q: " + q);
        N = p.multiply(q);
        System.out.println("Product of N: " + N);
        d = String.valueOf(N).length();
        //System.out.println("Length of N (d) : " + d);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        publicKey = publicKey(phi);
        privateKey = privateKey(publicKey);

    }

    // Function to generate random integers between a given range
    
    private int randomIntBetween(int i, int i1) {
        int result;
        do {
            result = (int) (Math.random() * i1) + i;
        } while (result < i || result > i1);
        return result;
    }

    // Generating 1024 bit ramdom primes which are of type bigInteger.
    
    private BigInteger randomBigIntBetween(int a, int b) {
        int rand = 0;
        while (rand < a || rand > b) {
            rand = (int) (Math.random() * 2048);
        }

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < rand; i++) {
            sb.append(new Random().nextInt(10));
        }
        return new BigInteger(sb.toString());
    }
    
    // Rabbin Millers Algorithm for Primality Test

    public static boolean probablePrime(BigInteger num1, int temp) {
        if (num1.compareTo(THREE) < 0)
            return true;
        int s = 0;
        BigInteger d = num1.subtract(ONE);
        while (d.mod(TWO).equals(ZERO)) {
            s++;
            d = d.divide(TWO);
        }
        for (int i = 0; i < temp; i++) {
            BigInteger a = uniformRandom(TWO, num1.subtract(ONE));
            BigInteger x = modPower(a, d, num1);
            if (x.equals(ONE) || x.equals(num1.subtract(ONE)))
                continue;
            int r = 1;
            for (; r < s; r++) {
                x = modPower(x, TWO, num1);
                if (x.equals(ONE))
                    return false;
                if (x.equals(num1.subtract(ONE)))
                    break;
            }
            if (r == s)
                return false;
        }
        return true;
    }

    // Function to implement Modular Exponential Formula for Miller Rabbin Test

    public static BigInteger modPower(BigInteger base, BigInteger n, BigInteger m) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(m);
        for (int idx = 0; idx < n.bitLength(); ++idx) {
            BigInteger testBit = base.shiftRight(1).and(BigInteger.ONE);
            if (testBit == BigInteger.ONE) {
                result = result.multiply(base).mod(m);
            }
            base = base.multiply(base).mod(m);
        }
        return result;
    }

    // Function to select random Integer for primality test
    
    private static BigInteger uniformRandom(BigInteger bottom, BigInteger top) {
        Random rnd = new Random();
        BigInteger res;
        do {
            res = new BigInteger(top.bitLength(), rnd);

        }
        while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
        return res;
    }

    // Extended Euclidean Algorithm to calculate the gcd of 2 numbers

    public static BigInteger getGcd(BigInteger a, BigInteger b) {
        BigInteger x = BigInteger.ZERO;
        BigInteger lastx = BigInteger.ONE;
        BigInteger y = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        while (!b.equals(BigInteger.ZERO))
        {
            BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
            BigInteger quotient = quotientAndRemainder[0];

            BigInteger temp = a;
            a = b;
            b = quotientAndRemainder[1];

            temp = x;
            x = lastx.subtract(quotient.multiply(x));
            lastx = temp;

            temp = y;
            y = lasty.subtract(quotient.multiply(y));
            lasty = temp;
        }
        return a;
    }


    // Function for Encrypt plain text

    BigInteger encryptPlainText(BigInteger plainText, BigInteger publicKey, BigInteger N) {

        return modExp(plainText, publicKey, N);
    }

    // Function for Decrypt cipher text

    BigInteger decryptCipherText(BigInteger cipherText, BigInteger privateKey, BigInteger N) {

        return modExp(cipherText, privateKey, N);
    }
    // Modular Exponentiation using Right to Left Binary method
    
    private BigInteger modExp(BigInteger text, BigInteger key, BigInteger N) {
        BigInteger res = ONE;

        text = text.mod(N);
        while (key.compareTo(ZERO) > 0) {

            if (key.mod(TWO).equals(ONE))

                res = (res.multiply(text)).mod(N);

            key = key.shiftRight(1);

            text = (text.multiply(text)).mod(N);
        }
        return res;
    }

    // Function to get publicKey 'e'

    BigInteger publicKey(BigInteger phi) {

        BigInteger publicKey = BigInteger.valueOf(0);

        BigInteger i = randomBigIntBetween(500, 1000);
        while (i.compareTo(phi) < 0) {
            if (getGcd(i, phi).equals(BigInteger.valueOf(1))) {
                publicKey = i;
                break;
            }
            i = i.add(BigInteger.valueOf(1));
        }
        System.out.println("Encryption Key (e): " + publicKey);
        return publicKey;
    }

    // Function to get Private Key d

    BigInteger privateKey(BigInteger publicKey) {
        while (phi.gcd(publicKey).compareTo(BigInteger.ONE) > 0 && publicKey.compareTo(phi) < 0) {
            publicKey.add(BigInteger.ONE);
        }
        BigInteger result = modInverse(publicKey, phi);
        while (result.compareTo(BigInteger.ZERO) < 0) {
            result = result.add(phi);
        }
        System.out.println("Decryption Key (d): " + result);
        return result;
        // return modInverse(publicKey, phi);
    }

    // Function to return Bezout's coefficients in Extented Euclidean Algorithm

    public static BigInteger modInverse(BigInteger key, BigInteger p) {
        BigInteger s, old_s;
        BigInteger t, old_t;
        BigInteger r, old_r;
        BigInteger quotient, temp;
        s = BigInteger.valueOf(0);
        old_s = BigInteger.valueOf(1);
        t = BigInteger.valueOf(1);
        old_t = BigInteger.valueOf(0);
        r = p;
        old_r = key;
        while (r != BigInteger.valueOf(0)) {
            quotient = old_r.divide(r);
            temp = r;
            r = old_r.subtract(quotient.multiply(r));
            old_r = temp;
            temp = s;
            s = old_s.subtract(quotient.multiply(s));
            old_s = temp;
            temp = t;
            t = old_t.subtract(quotient.multiply(t));
            old_t = temp;
        }
        // System.out.println("Value of r :" +r );
        // System.out.println("Decryption key d:" +old_t);
        return old_s;
    }

    // Function to loop each block of plain text
    
    public String encrypt(char[] input) {
        mb = new MyBlocks();
        length = input.length;
        String[] blocks = mb.getBlocks(input, d);
        String ct;
        StringBuilder ptxt = new StringBuilder();

        for (String s : blocks) {
            ct = encryptPlainText(new BigInteger(s.getBytes()), publicKey, N).toString();
            ptxt.append(ct).append("-");
        }
        return ptxt.toString();
    }

    // Function to loop each block of cipher text
    
    public String decrypt(String encrypted) {

//        char[] s1 = encrypted.split("-")[0].toCharArray();
        String[] blocks = encrypted.split("-");
        StringBuilder ptxt2 = new StringBuilder();
        BigInteger pt;

        for (String s : blocks) {
            if (!s.isEmpty()) {
                pt = decryptCipherText(new BigInteger(s), privateKey, N);
                String ste = new String(pt.toByteArray());
                ptxt2.append(ste);
            }
        }
       // System.out.println("PLAIN:" + ptxt2);
        return mb.getM(ptxt2.toString(), length);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();
        System.out.print("Enter a Message : ");
        Scanner in = new Scanner(System.in);
        char[] input = in.nextLine().toCharArray();
        String encrypted = rsa.encrypt(input);
        System.out.println("Encrypted TEXT : " + encrypted);
        String decrypted =rsa.decrypt(encrypted);

        System.out.println("Decrypted Message : " + decrypted);

    }
}

// Function to divide the input string into equal size blocks

class MyBlocks {
    private static int blockSize = 250; //default value
    private String st = "";

    public String getplain() {
        return st;
    }

    // Take input String, convert it into 3 digit ascii values, if 3 digits are not present add zero at the front

    public String[] getBlocks(char[] arr,int d) {

        st = "";
        for (int i = 0; i < arr.length; i++) {
            int ch = (int) arr[i];
            if (String.valueOf(ch).length() < 3) {
                st = st + "0" + ch;
            } else {
                st = st + "" + ch;
            }
        }
        System.out.println("Plain Text : " + st);
        int count = 0;
        //The block-size cannot be more than 250 for encryption/decryption. If d/3 greater than 250, use default blockSize which is 250
        int block_size = d / 3 > blockSize ? blockSize - 1 : d / 3 - 1;
        int blocks_count;
      //  System.out.println("Block size : " + block_size);
        if (st.length() % block_size == 0)
            blocks_count = st.length() / block_size;
        else
            blocks_count = st.length() / block_size + 1;

        String[] blocks = new String[blocks_count];
        String s = "";
        int num_blocks = 0;
        for (int a = 0; a < st.length(); a++) {
            s = s + st.charAt(a);
            count++;
            if (count == block_size) {
                blocks[num_blocks] = s;
                //System.out.println("blocks1 : " + s);
                count = 0;
                s = "";
                num_blocks++;
            }
        }
        
        // If each block is not of required length, append 0's 
        
        if (count != 0) {

            int sub_string_length = s.length();
            String zero_string = "";
            for (int new_length = sub_string_length; new_length < block_size; new_length++) {
                zero_string = zero_string + "0";
            }
            blocks[num_blocks] = s + zero_string;
           // System.out.println("blocks :" + s + zero_string);
            num_blocks++;
            s = "";
        }
        return blocks;
    }

    // Function to obtain decrypted text after decryption
    
    public String getM(String s, int lg) {

        int count = 0;
        int t = 3;
        String[] blocks = new String[lg];
        String message = "";
        for (int a = 0; a < lg; a++) {

            String b = blocks[a] = s.substring(count, t);
            message = message + Character.toString((char) Integer.parseInt(b));
            count = count + 3;
            t = t + 3;
        }
        return message;
    }

}