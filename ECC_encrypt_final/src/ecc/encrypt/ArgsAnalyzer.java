package ecc.encrypt;

/**
 * ArgsAnalyzer is a class analyzing command line that users input.
 * 
 */
public class ArgsAnalyzer {

	private static String keyId = "-k";
	private static String keyGen = "-g";
	private static String importFile = "-i";
	private static String exportFile = "-o";
	private static String enMsg = "-em";
	private static String deMsg = "-dm";
	private static String enFile = "-ef";
	private static String deFile = "-df";
	private static String sign = "-s";
	private static String verify = "-v";
	private static String help = "-h";
	private static String list = "-list";

	public static int analyze(String[] args) {
		if (args.length < 1)
			return -1;
		// generate new key pair - 0
		if (args[0].equals(keyId) && args[2].equals(keyGen) && args.length == 3)
			return 0;
		// export public key - 1
		if (args[0].equals(keyId) && args[2].equals(exportFile)
				&& args.length == 4)
			return 1;
		// import public key - 2
		if (args[0].equals(keyId) && args[1].equals(importFile)
				&& args.length == 3)
			return 2;
		// encrypt message - 3
		if (args[0].equals(enMsg) && args[3].equals(exportFile)
				&& args.length == 5)
			return 3;
		// decrypt message - 4
		if (args[0].equals(deMsg) && args[3].equals(importFile)
				&& args.length == 5)
			return 4;
		// encrypt file - 5
		if (args[0].equals(enFile) && args[3].equals(importFile)
				&& args[5].equals(exportFile) && args.length == 7)
			return 5;
		// decrypt file - 6
		if (args[0].equals(deFile) && args[3].equals(importFile)
				&& args[5].equals(exportFile) && args.length == 7)
			return 6;
		// sign a file - 7
		if (args[0].equals(sign) && args[2].equals(importFile)
				&& args[4].equals(exportFile) && args.length == 6)
			return 7;
		// verify a signature - 8
		if (args[0].equals(verify) && args[2].equals(importFile)
				&& args.length == 5)
			return 8;
		if (args[0].equals(help) && args.length == 1)
			return 9;
		if (args[0].equals(list) && args.length == 1)
			return 10;

		// invalid arguments
		return -1;
	}
}
