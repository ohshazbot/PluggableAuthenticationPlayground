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
import tokens.Token;
import tokens.UsernamePasswordToken;

/**
 * Created with IntelliJ IDEA. User: chris Date: 8/20/12 Time: 12:28 PM To change this template use File | Settings | File Templates.
 */
public class PlugClient {
  protected PluggableSecurityTest.Client proxy;
  protected TTransport transport;
  
  public PlugClient() throws TTransportException {
    final TSocket socket = new TSocket("localhost", 50228);
    socket.setTimeout(600000);
    transport = new TFramedTransport(socket);
    final TProtocol protocol = new TCompactProtocol(transport);
    proxy = new PluggableSecurityTest.Client(protocol);
    transport.open();
  }
  
  public void close() throws TException {
    transport.close();
  }
  
  public boolean ping() {
    try {
      return proxy.ping();
    } catch (TException e) {
      e.printStackTrace();
      return false;
    }
  }
  
  public boolean authenticate(Token token) throws PlugException, IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream ();
      ObjectOutputStream objOut = new ObjectOutputStream(out);
      objOut.writeObject(token);
      out.close();
      objOut.close();
      return proxy.authenticate(ByteBuffer.wrap(out.toByteArray()));
    } catch (TException e) {
      e.printStackTrace();
      return false;
    }
  }
  
  public boolean nonauthenticateoperation(String user, Token token, String s) throws PlugException, IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream ();
      ObjectOutputStream objOut = new ObjectOutputStream(out);
      objOut.writeObject(token);
      out.close();
      objOut.close();
      return proxy.nonauthenticateoperation(user, ByteBuffer.wrap(out.toByteArray()), s);
    } catch (TException e) {
      e.printStackTrace();
      return false;
    }
    
  }
  
  public static void main(String args[]) throws TTransportException, PlugException, IOException {
    AtomicBoolean stop = new AtomicBoolean(false);
    PlugServer server = new PlugServer(stop);
    Thread t = new Thread(server);
    t.start();
    
    PlugClient client = new PlugClient();
    
    System.out.println("PING? " + client.ping());
    System.out.println("PING? " + client.ping());
    System.out.println("PING? " + client.ping());
    System.out.println("PING? " + client.ping());
    System.out.println("PING? " + client.ping());
    
    Token token = new UsernamePasswordToken("user", "pass".getBytes());
//    Token token = new TicketToken("userpass".getBytes());
    System.out.println("AUTHENTICATE! " + client.authenticate(token));
    
    System.out.println("SOMETHING ELSE! " + client.nonauthenticateoperation("user", token, "I'm a message being printed server side"));
    System.out.println("SOMETHING ELSE! " + client.nonauthenticateoperation("fake", token, "I'm a message being printed server side"));
    
    stop.set(true);
    t.interrupt();
  }
}
