















/*
 * This is a generated file. Do not edit this file!
 */
package com.svi.asserter;

import java.util.Map;
import java.beans.BeanInfo;

import java.beans.BeanDescriptor;
import java.beans.MethodDescriptor;
import java.beans.PropertyDescriptor;
import java.beans.ParameterDescriptor;
import java.beans.EventSetDescriptor;
import java.beans.IntrospectionException;

import weblogic.management.internal.mbean.BeanInfoBinder;
import weblogic.management.internal.mbean.BeanInfoImpl;
import weblogic.management.internal.mbean.BeanInfoHelper;

import weblogic.management.commo.RequiredModelMBeanWrapper;

import com.svi.asserter.JWTtokenIdentityAsserterMBean;

/**
 * @copyright Copyright (c) 2003,2014, Oracle and/or its affiliates. All rights reserved.
 * @author Copyright (c) 2003,2014, Oracle and/or its affiliates. All rights reserved.
 * @version 0.1
 */
public class JWTtokenIdentityAsserterMBeanImplBeanInfo
  extends weblogic.management.security.authentication.IdentityAsserterMBeanImplBeanInfo
{

  public JWTtokenIdentityAsserterMBeanImplBeanInfo(boolean readOnly, String targetVersion)
      throws IntrospectionException {
    super(readOnly, targetVersion);
  }
  // constructor
  public JWTtokenIdentityAsserterMBeanImplBeanInfo()
    throws IntrospectionException {

  }


  public static final Class INTERFACE_CLASS = com.svi.asserter.JWTtokenIdentityAsserterMBean.class;


  protected BeanDescriptor buildBeanDescriptor() {

    Class beanClass = null;
    try {
      beanClass = Class.forName("com.svi.asserter.JWTtokenIdentityAsserterMBeanImpl");
    } catch (Throwable ignore) {
      beanClass = INTERFACE_CLASS;
    }
    
    BeanDescriptor beanDescriptor =
      new BeanDescriptor(  beanClass, null /*customizer*/ );

    beanDescriptor.setValue("dynamic",Boolean.TRUE);
     beanDescriptor.setValue("package","com.svi.asserter");
    String description = new String(
          
           "No description provided. " +  ""    ).intern();
    beanDescriptor.setShortDescription(description);
    beanDescriptor.setValue("description", description);
    beanDescriptor.setValue("interfaceclassname",  "com.svi.asserter.JWTtokenIdentityAsserterMBean");
    beanDescriptor.setValue("generatedByWLSInfoBinder", Boolean.TRUE);

    return beanDescriptor;
  }

  /**
   * Get the attribute infos for this class and all of it parent
   * classes combined.
   *
   * @param descriptors the set to add you descriptors to.
   */
  protected void buildPropertyDescriptors( Map descriptors )
         throws IntrospectionException {
    PropertyDescriptor currentResult = null;
    // PROPERTY ActiveTypes
    {
    if ( !descriptors.containsKey("ActiveTypes"))
    {
      String getterName = "getActiveTypes";
      String setterName = null;
      if (!readOnly)
        setterName = "setActiveTypes";
      currentResult =
        new PropertyDescriptor( "ActiveTypes",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "ActiveTypes", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = "Authorization"
     setPropertyDescriptorDefault(currentResult, BeanInfoHelper.stringArray("Authorization"));
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    // PROPERTY Base64DecodingRequired
    {
    if ( !descriptors.containsKey("Base64DecodingRequired"))
    {
      String getterName = "getBase64DecodingRequired";
      String setterName = null;
      if (!readOnly)
        setterName = "setBase64DecodingRequired";
      currentResult =
        new PropertyDescriptor( "Base64DecodingRequired",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "Base64DecodingRequired", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = false
     setPropertyDescriptorDefault(currentResult, new Boolean(false));
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    // PROPERTY Description
    {
    if ( !descriptors.containsKey("Description"))
    {
      String getterName = "getDescription";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "Description",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "Description", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = "WebLogic JWT Token Identity Asserter Provider"
     setPropertyDescriptorDefault(currentResult, "WebLogic JWT Token Identity Asserter Provider");
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    // PROPERTY Name
    {
    if ( !descriptors.containsKey("Name"))
    {
      String getterName = "getName";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "Name",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "Name", currentResult );
      currentResult.setValue("description",     
           " " +  "");
 // default = "JWTtokenIdentityAsserter"
     setPropertyDescriptorDefault(currentResult, "JWTtokenIdentityAsserter");
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "RealmAdministrator");
      currentResult.setValue("VisibleToPartitions","ALWAYS");
      currentResult.setValue("owner","RealmAdministrator");
    }
    }
    // PROPERTY ProviderClassName
    {
    if ( !descriptors.containsKey("ProviderClassName"))
    {
      String getterName = "getProviderClassName";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "ProviderClassName",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "ProviderClassName", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = "com.svi.asserter.JWTtokenIdentityAsserterProviderImpl"
     setPropertyDescriptorDefault(currentResult, "com.svi.asserter.JWTtokenIdentityAsserterProviderImpl");
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    // PROPERTY Realm
    {
    if ( !descriptors.containsKey("Realm"))
    {
      String getterName = "getRealm";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "Realm",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "Realm", currentResult );
      currentResult.setValue("description",     
           "Returns the realm that contains this security provider. " + 
           "Returns null if this security provider is not contained by a realm. " +  "");
      currentResult.setValue("relationship", "reference");
         currentResult.setValue("transient", Boolean.TRUE);
     currentResult.setValue("dynamic", Boolean.FALSE);
     }
    }
    // PROPERTY SupportedTypes
    {
    if ( !descriptors.containsKey("SupportedTypes"))
    {
      String getterName = "getSupportedTypes";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "SupportedTypes",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "SupportedTypes", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = "Authorization"
     setPropertyDescriptorDefault(currentResult, BeanInfoHelper.stringArray("Authorization"));
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    // PROPERTY Version
    {
    if ( !descriptors.containsKey("Version"))
    {
      String getterName = "getVersion";
      String setterName = null;
      currentResult =
        new PropertyDescriptor( "Version",
             com.svi.asserter.JWTtokenIdentityAsserterMBean.class,
             getterName,
             setterName);
      descriptors.put( "Version", currentResult );
      currentResult.setValue("description",     
           "No description provided. " +  "");
 // default = "1.0"
     setPropertyDescriptorDefault(currentResult, "1.0");
        currentResult.setValue("dynamic", Boolean.FALSE);
     currentResult.setValue("owner", "");
    }
    }
    super.buildPropertyDescriptors( descriptors );
  }


  /**
   * Get the method infos for a subset of the overall methods types.
   *
   */
  private void fillinFactoryMethodInfos( Map descriptors )
         throws IntrospectionException,
                java.lang.NoSuchMethodException {

    MethodDescriptor currentResult;

  }

  /**
   * Get the method infos for a subset of the overall methods types.
   *
   */
  private void fillinCollectionMethodInfos( Map descriptors )
         throws IntrospectionException,
                java.lang.NoSuchMethodException {

    MethodDescriptor currentResult;

  }

  /**
   * Get the method infos for a subset of the overall methods types.
   *
   */
  private void fillinFinderMethodInfos( Map descriptors )
         throws IntrospectionException,
                java.lang.NoSuchMethodException {

    MethodDescriptor currentResult;

  }

  /**
   * Get the method infos for a subset of the overall methods types.
   *
   */
  private void fillinOperationMethodInfos( Map descriptors )
         throws IntrospectionException,
                java.lang.NoSuchMethodException {

    MethodDescriptor currentResult;

  }

  /**
   * Get the method infos for this class and all of it parent
   * classes combined.
   *
   * @param descriptors the set to add to.
   */
  protected void buildMethodDescriptors( Map descriptors )
         throws IntrospectionException,
                java.lang.NoSuchMethodException {

    fillinFinderMethodInfos(descriptors);
    if ( !readOnly ) {
      fillinCollectionMethodInfos(descriptors);
      fillinFactoryMethodInfos(descriptors);
    }
    fillinOperationMethodInfos(descriptors);
     super.buildMethodDescriptors(descriptors);
  }

  /**
    * Get the event infos for this class and all of it parent
    * classes combined.
    *
    * @param descriptors the set to add to.
    */
  protected void buildEventSetDescriptors(  Map descriptors )
       throws IntrospectionException {
    // TODO: this is not yet implemented
  }
}
