package com.github.jwcranford.scryptbc.app;

import com.github.jwcranford.scryptbc.Header;
import com.github.jwcranford.scryptbc.ScryptException;
import com.github.jwcranford.scryptbc.ScryptFile;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

@Command(name="scryptbc",
        description="Encrypt and decrypt files with a Bouncycastle-based version of the scrypt utility",
        mixinStandardHelpOptions = true,
        version="scryptbc 0.2.0",
        synopsisSubcommandLabel = "COMMAND",
    subcommands = {CommandLine.HelpCommand.class}
)
public class App {

    @Command(description = "Decrypt infile and write the result to outfile. " +
            "The user will be prompted to enter the passphrase used at encryption time to derive the encryption key.")
    public int dec(
            @Option(
                    names = {"-v", "--verbose"},
                    description = "Print encryption parameters (N, r, p) and memory/cpu limits to standard error"
            ) boolean verbose,
            @Parameters(index="0", paramLabel = "infile") Path infile,
            @Parameters(index="1", paramLabel = "outfile") Path outfile
    ) {
        Console console = System.console();
        try {
            char[] password = readPassword(console, "Enter password: ");
            ScryptFile file = ScryptFile.decrypt(infile.toFile(), password, outfile.toFile());
            if (verbose) {
                printInfo(file.getHeader());
            }
            return CommandLine.ExitCode.OK;
        } catch (IOException | ScryptException e) {
            System.err.println("Decrypted content not valid/complete: " + e);
            if (outfile != null) {
                try {
                    Files.delete(outfile);
                } catch (IOException ex) {
                    System.err.println("Unable to delete file " + outfile + ": " + e);
                }
            }
            return CommandLine.ExitCode.SOFTWARE;
        }
    }

    @Command(description = "Encrypt infile and write the result to outfile. The user will be prompted to enter a " +
            "passphrase (twice) to derive the encryption key.")
    public int enc(
            @Option(
                    names = {"-v", "--verbose"},
                    description = "Print encryption parameters (N, r, p) and memory/cpu limits to standard error"
            ) boolean verbose,
            @Option(
                    names = {"--logN"},
                    description = "Set the work parameter N to 2^value.  If --logN is set, -r and -p must also be set."
            ) byte logN,
            @Option(
                    names = {"-r"},
                    description = "Set the work parameter r to value.  If -r is set, --logN and -p must also be set."
            ) int r,
            @Option(
                    names = {"-p"},
                    description = "Set the work parameter p to value.  If -p is set, --logN and -r must also be set."
            ) int p,
            @Parameters(index="0", paramLabel = "infile") Path infile,
            @Parameters(index="1", paramLabel = "outfile") Path outfile
    ) {
        Console console = System.console();
        try {
            char[] password = readPassword(console, "Enter password: ");
            char[] password2 = readPassword(console, "Enter password again: ");
            if (Arrays.equals(password, password2)) {
                var file = new ScryptFile(logN, r, p);
                file.encrypt(infile.toFile(), password, outfile.toFile());
                if (verbose) {
                    printInfo(file.getHeader());
                }
                return CommandLine.ExitCode.OK;
            } else {
                System.err.println("Passwords not equal");
                return CommandLine.ExitCode.SOFTWARE;
            }
        } catch (IOException | ScryptException e) {
            System.err.println("Encrypted content not valid/complete: " + e);
            if (outfile != null) {
                try {
                    Files.delete(outfile);
                } catch (IOException ex) {
                    System.err.println("Unable to delete file " + outfile + ": " + e);
                }
            }
            return CommandLine.ExitCode.SOFTWARE;
        }
    }

    @Command(description = "Provide information about the encryption parameters used for infile.")
    public int info(
            @Parameters(index="0", paramLabel = "infile") Path infile
    ) {
        try {
            try (InputStream inputStream = Files.newInputStream(infile)) {
                Header header = Header.decode(inputStream);
                printInfo(header);
            }
            return CommandLine.ExitCode.OK;
        } catch (IOException | ScryptException e) {
            System.err.println(e);
            return CommandLine.ExitCode.SOFTWARE;
        }
    }

    private static void printInfo(Header header) {
        System.err.format("Parameters used: log2N = %d; N = %,d; r = %d; p = %d",
                header.getLog2N(),
                1 << header.getLog2N(),
                header.getR(),
                header.getP());
        System.err.println();

        System.err.format("\tDecrypting this file requires at least %,d MB of memory.",
                header.calcMbRequired());
        System.err.println();
    }

    private char[] readPassword(Console console, String prompt) throws IOException {
        if (console == null) {
            System.out.print(prompt);
            System.out.flush();
            return new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
        } else {
            return console.readPassword(prompt);
        }
    }


    public static void main(String[] args) {
        var app = new CommandLine(new App());
        int exitCode = app.execute(args);
        System.exit(exitCode);
    }
}
