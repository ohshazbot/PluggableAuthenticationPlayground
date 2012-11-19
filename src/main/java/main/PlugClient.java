package main;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

import thrift.PlugException;
import thrift.PluggableSecurityTest;
import tokens.AuthenticationToken;
import tokens.KerberosToken;
import authenticators.KerberosAuthenticator;
import authenticators.TicketAuthenticator;
import authenticators.UserPassAuthenticator;

public class PlugClient {
  protected PluggableSecurityTest.Client proxy;
  protected TTransport transport;
  
  public PlugClient(String host, int port) throws TTransportException {
    final TSocket socket = new TSocket(host, port);
    socket.setTimeout(600000);
    transport = new TFramedTransport(socket);
    final TProtocol protocol = new TCompactProtocol(transport);
    proxy = new PluggableSecurityTest.Client(protocol);
    transport.open();
  }
  

  public boolean ping() {
    try {
      return proxy.ping();
    } catch (TException e) {
      e.printStackTrace();
      return false;
    }
  }
  
  public boolean authenticate(AuthenticationToken token) throws PlugException, IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ObjectOutputStream objOut = new ObjectOutputStream(out);
      objOut.writeObject(token);
      out.close();
      objOut.close();
      return proxy.authenticate(ByteBuffer.wrap(out.toByteArray()));
    } catch (TException e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }
  
  public String authenticationClass() throws TException {
    return proxy.authenticationClass();
  }
  
  public boolean nonauthenticateoperation(AuthenticationToken token, String s) throws PlugException, IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ObjectOutputStream objOut = new ObjectOutputStream(out);
      objOut.writeObject(token);
      out.close();
      objOut.close();
      return proxy.nonauthenticateoperation(ByteBuffer.wrap(out.toByteArray()), s);
    } catch (TException e) {
      e.printStackTrace();
      return false;
    }
    
  }
  
  public static void main(String args[]) throws Exception {
    // AtomicBoolean stop = new AtomicBoolean(false);
    // PlugServer server = new PlugServer(stop, 50228);
    // Thread t = new Thread(server);
    // t.start();
    //
    // PlugServer server2 = new PlugServer(stop, 50229);
    // Thread t2 = new Thread(server2);
    // t2.start();
    //
    // Thread.sleep(900);
    try {
      KerberosToken token;
      
      PlugClient client = new PlugClient("localhost", 50228);
      
      System.out.println("PING? " + client.ping());
      System.out.println("PING? " + client.ping());
      System.out.println("PING? " + client.ping());
      System.out.println("PING? " + client.ping());
      System.out.println("PING? " + client.ping());
      
      String auth = client.authenticationClass();
      System.out.println(auth);
      // AuthenticationToken token;
      // if (auth.equals("authenticators.UserPassAuthenticator"))
      // token = UserPassAuthenticator.getToken("upuser", "pass".getBytes());
      // else if (auth.equals("authenticators.TicketAuthenticator"))
      // token = TicketAuthenticator.getToken("ticketuser_pass".getBytes());
      // else if (auth.equals("authenticators.KerberosAuthenticator"))
//      token = KerberosAuthenticator.getToken("user", "password".toCharArray());
      token = KerberosAuthenticator.getToken("user", "password".toCharArray());
//      token = KerberosAuthenticator.getToken("test", "test".toCharArray());
      // else {
      // throw new Exception("Unknown authentication mechanism");
      // }

      token.user = "test";
      System.out.println("AUTHENTICATE! " + client.authenticate(token));
      
      System.out.println("SOMETHING ELSE! " + client.nonauthenticateoperation(token, "I'm a message being printed server side"));
      token.user = "user";
      Thread.sleep(5000);
      System.out.println("SOMETHING ELSE! " + client.nonauthenticateoperation(token, "I'm a message being printed server side"));
      
      // client = new PlugClient("localhost", 50229);
      // System.out.println("SOMETHING ELSE! " + client.nonauthenticateoperation(token, "I'm a message being printed server side"));
      
    } finally {
      // stop.set(true);
      // t.interrupt();
      // t2.interrupt();
    }
  }
}
