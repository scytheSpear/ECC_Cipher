import java.io.*;
import java.math.*;
import java.util.Scanner;

public class Decrypt {

	static final BigInteger Zero = new BigInteger("0");
	static final BigInteger One = new BigInteger("1");
	static final BigInteger MinusOne = new BigInteger("-1");

	static final int MAX_BUFFER_SIZE = 2048;
	static final int MAX_KEY_SIZE = 160;
	static final int MAX_ASCII = 255;
	
   static Curve C = Curve.curve;
   static BigInteger p = C.p;
   static BigInteger A = C.A;
   static BigInteger B = C.B;
   static BigInteger q = C.q;
   static BigInteger h = C.h;
   static Point G  = new Point(C.x, C.y);
          
public static void main(String[] args) throws Exception, IOException {
	  
	Function f = new Function();
	Scanner in = new Scanner(System.in);
	
	/*
	//Take input and encoding to a Point array Ma[] 
	
	
	String mes1 = "0";
	char[] Mes;
	Point[] Ma;
	Point[] Ca;
	BigInteger As;
	BigInteger Bs;
	
	System.out.println("input a string");
	mes1 = in.nextLine();
	//System.out.println("input key As and Bs");
	//As = in.nextBigInteger();
	//Bs = in.nextBigInteger();
	As = f.RandomNum();
	Bs = f.RandomNum();
	Point Bp = G.multiply(Bs);
	Point Ap = G.multiply(As);
	
	Mes =new char[mes1.length()];
	Ca= new Point[mes1.length()];

	Point C1 = f.encryptASG(As, Bp);
	System.out.println("C1 y: " + C1.y);
	System.out.println("Randomtest As: "+ As + "Bs :" + Bs);
	
	
	
	for(int i = 0; i < mes1.length() ; i++ )
	{
		
		Mes[i] = mes1.charAt(i);
		
		
		System.out.println( "Message char Array: "+ Mes[i]);	
		//System.out.println(Encoding (Mes[i], C));

		//Take public key of B point Bp and private key of A big int As as input and encrpt message to point array Ma
		Ma = new Point[mes1.length()];
		Ma[i] = f.Encoding(Mes[i],C);
		
		if (f.PointOnCurve(Ma[i],C))
		{
		System.out.println("MArray y: " + Ma[i].y);
		
		Point C2 = f.encryptBPM(Ma[i], As, Bp);
		
		System.out.println("C2 y: "+C2.y);
		
		Ca[i] = C2;
		
		System.out.println("C2Array y: "+Ca[i].y);
		}
		else
		{
			System.out.println("M is not on C");
		}
	}
		*/
	
	//BigInteger Bs = f.RandomNum() ;
	System.out.println("Input recipient privite key");
	BigInteger Bs = in.nextBigInteger();
	
	Point Bp = G.multiply(Bs);
	System.out.println(Bp.x);
	System.out.println(Bp.y);
	
	System.out.println("Input recipient Public key Bp.x and Bp.y");
	Point Ap = new Point(BigInteger.ZERO,BigInteger.ZERO);
	System.out.println("Enter ap.x");
	Ap.x = in.nextBigInteger();
	System.out.println("Enter Ap.y");
	Ap.y = in.nextBigInteger();
	Ap = new Point(Ap.x , Ap.y);
	
	System.out.println("input sender name");
	String sendername = in.next();
	
	
	FileInputStream fin = new FileInputStream("E:\\point.ser");
	ObjectInputStream ois = new ObjectInputStream(fin);
	Point Preadfile[] = (Point[]) ois.readObject();
	
	Point C1 = Preadfile[0];
	Point s = Preadfile[1];
	
	boolean x = f.verifying (s, Ap ,sendername);
	System.out.println(x);
	
	if(x)
	{
	char[] msg = new char[Preadfile.length - 2];
	Point[] Msg = new Point[Preadfile.length - 2];
	
	
        for (int i=0; i < Preadfile.length -2; i++ )
        {
            Msg[i] = f.decryptM(Bs, C1 , Preadfile[i+2]);
            msg[i] = f.Decoding(Msg[i], C);
		
		System.out.println("C2 y: " + Preadfile[i+1].y);
		System.out.println("Point M y: " + Msg[i].y);
		System.out.println("charArray: " + msg[i]);
		
        }
	
		String Pm  = String.valueOf(msg);
		System.out.println("plaintext: "+Pm);
	}	
	else
	{
		System.out.println("sender name invalide");
	}
}
}


