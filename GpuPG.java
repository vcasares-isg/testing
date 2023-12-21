package py.com.bancoamambay.bancaconsumo.fe.seguridad;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.logging.Level;
import py.com.bancoamambay.bancaconsumo.fe.utils.ParametrosDinamicosBean;
import py.com.bancoamambay.bancaconsumo.fe.utils.ProcessStreamReader;

/**
 * A class that implements PGP interface for Java.
 * <P>
 * It calls gpg (GnuPG) program to do all the PGP processing. $Id:$
 *
 * @author	LiLo Argaña : ricardoargana@gmail.com
 * @author .
 * @author Based on a class GnuPG by Yaniv Yemini
 * @author .
 * @author	Original javadoc included:
 * @author	.
 * @author	License: GPL v3
 * @author	Latest version of this code can be found at:
 * @author	http://www.macnews.co.il/mageworks/java/gnupg/
 * @author	.
 * @author	Based on a class GnuPG by John Anderson, which can be found
 * @author	at: http://lists.gnupg.org/pipermail/gnupg-devel/2002-February/018098.html
 *
 * @see	GnuPG - http://www.gnupg.org/
 */
public class GpuPG {

  private static final String MSG_ERROR_ENCRIPTAR;
  private static final String GNU_PG_EXE;
  private static final String ENCRIPTAR_FIRMADO_ARGS;
  private static final String RECIPIENT;
  private static final String BASE_ARGS;

  static {
    ParametrosDinamicosBean pdb = ParametrosDinamicosBean.getInstance();
    MSG_ERROR_ENCRIPTAR = "No se pudo encriptar";
    BASE_ARGS = " --batch --armor --output -";
    ENCRIPTAR_FIRMADO_ARGS = "--sign --encrypt --recipient";
//        GNU_PG_EXE = "C:\\Program Files (x86)\\GNU\\GnuPG\\gpg";
//        RECIPIENT = "idv@agz.com.py";
    GNU_PG_EXE = pdb.getGNU_PG_EXE();
    RECIPIENT = pdb.getGNU_PG_RECIPIENT();
  }

  public static File encriptarFirmado(String inputStr) throws Exception {
    return ejecutar(inputStr, ENCRIPTAR_FIRMADO_ARGS + " " + RECIPIENT);
  }

  private static File ejecutar(String inputStr, String args) throws Exception {

    Process p;
    File file = null;
    OutputStreamWriter fw = null;

    try {
      file = File.createTempFile(".00", null);
      fw = new OutputStreamWriter(new FileOutputStream(file), Charset.forName("CP1252"));
      fw.write(inputStr);
      fw.flush();
      fw.close();
    } catch (IOException ex) {
      py.com.bancoamambay.utils.LoggerInitializer.getLogger().log(Level.SEVERE, null, ex);
      throw new Exception(MSG_ERROR_ENCRIPTAR);
    }finally {
      if (fw != null) {

        fw.close();
      }
    }

    String fullCommand = GNU_PG_EXE + BASE_ARGS + " " + args + " " + file.getPath();
    ProcessStreamReader stdOut;

    try {
      p = Runtime.getRuntime().exec(fullCommand);
      stdOut = new ProcessStreamReader(p.getInputStream());

      stdOut.start();
      if (inputStr != null) {
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(p.getOutputStream()));
        out.write(inputStr);
        out.close();
      }
      p.waitFor();
      stdOut.join();

    } catch (Exception e) {
      py.com.bancoamambay.utils.LoggerInitializer.getLogger().log(Level.SEVERE, null, e);
      throw new Exception(MSG_ERROR_ENCRIPTAR, e);
    }

    try {
      if (p.exitValue() != 0) {
        py.com.bancoamambay.utils.LoggerInitializer.getLogger().log(Level.INFO, ">>>ERROR CODE {0}", p.exitValue());
        throw new Exception(MSG_ERROR_ENCRIPTAR, new Exception("ERROR CODE " + p.exitValue()));
      }
    } catch (IllegalThreadStateException e) {
      py.com.bancoamambay.utils.LoggerInitializer.getLogger().log(Level.SEVERE, null, e);
      throw new Exception(MSG_ERROR_ENCRIPTAR, e);
    }
    FileOutputStream fileOutputStream = null;
    try {
      //new FileOutputStream(file).write(stdOut.getString().getBytes("UTF-8"));
      fileOutputStream = new FileOutputStream(file);
      fileOutputStream.write(stdOut.getString().getBytes("UTF-8"));
    } catch (IOException ex) {
      py.com.bancoamambay.utils.LoggerInitializer.getLogger().log(Level.SEVERE, null, ex);
      throw new Exception(MSG_ERROR_ENCRIPTAR, new Exception("Escribiendo archivo."));
    }finally {
      if (fileOutputStream != null) {

          fileOutputStream.close();

      }
    }

    return file;
  }
}
