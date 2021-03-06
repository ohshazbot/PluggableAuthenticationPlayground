package main;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.ByteBuffer;
import java.util.Random;

import javax.security.auth.login.LoginException;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.server.THsHaServer;
import org.apache.thrift.server.TServer;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TNonblockingServerSocket;
import org.ietf.jgss.GSSException;

import thrift.PlugException;
import thrift.PluggableSecurityTest;
import tokens.AuthenticationToken;
import authenticators.Authenticator;
import authenticators.KerberosAuthenticator;
import authenticators.TicketAuthenticator;
import authenticators.UserPassAuthenticator;

;

public class ServerImpl implements PluggableSecurityTest.Iface {
  KerberosAuthenticator auth;
  boolean last = false;
  TServer server;
  
  @Override
  public boolean ping() throws TException {
    last = !last;
    return last;
  }
  
  @Override
  public boolean authenticate(ByteBuffer tokenBytes) throws PlugException, TException {
    return auth.authenticate(getToken(tokenBytes));
  }
  
  private AuthenticationToken getToken(ByteBuffer tokenBytes) throws TException {
    ByteArrayInputStream byteIn = new ByteArrayInputStream(tokenBytes.array());
    ObjectInputStream in;
    try {
      in = new ObjectInputStream(byteIn);
      AuthenticationToken token = (AuthenticationToken) in.readObject();
      in.close();
      byteIn.close();
      return token;
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      throw new TException(e);
    } catch (ClassNotFoundException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
      throw new TException(e);
    }
  }
  
  public void startServer(final Integer port) throws Exception {
    TNonblockingServerSocket socket = new TNonblockingServerSocket(port);
    final PluggableSecurityTest.Processor<PluggableSecurityTest.Iface> processor = new PluggableSecurityTest.Processor<PluggableSecurityTest.Iface>(this);
    
    THsHaServer.Args args = new THsHaServer.Args(socket);
    args.processor(processor);
    args.transportFactory(new TFramedTransport.Factory());
    args.protocolFactory(new TCompactProtocol.Factory());
    server = new THsHaServer(args);
    
    Thread t = new Thread("thrift server") {
      public void run() {
        System.out.println("Starting server on port " + port + " ...");
        server.serve();
      }
    };
    t.start();
    
  }
  
  public ServerImpl() throws GSSException, LoginException {
    // Random r = new Random();
    // if (r.nextBoolean())
    // auth = new UserPassAuthenticator();
    // else
    // auth = new TicketAuthenticator();'
    auth = new KerberosAuthenticator();
  }
  
  public void close() {
    server.stop();
  }
  
  @Override
  public boolean nonauthenticateoperation(ByteBuffer token, String operationRelatedData) throws PlugException, TException {
    AuthenticationToken t = getToken(token);
    if (auth.authenticate(t))
      try {
        System.out.println("User " + auth.getUser(t) + " is doing " + operationRelatedData);
        return true;
      } catch (Exception e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
        return false;
      }
    return false;
    // }
    // return false;
  }
  
  @Override
  public String authenticationClass() throws TException {
    return auth.getClass().getCanonicalName();
  }
}
