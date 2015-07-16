/**
 * CVSS v2 Java Data Structure 
 * Copyright (c) 2015 - Mattia Zago 
 * <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 * 
 * NVD Common Vulnerability Scoring System Support v2
 * The Common Vulnerability Scoring System (CVSS) provides an open framework 
 * for communicating the characteristics and impacts of IT vulnerabilities. 
 * CVSS consists of 3 groups: Base, Temporal and Environmental. Each group 
 * produces a numeric score ranging from 0 to 10, and a Vector, a compressed 
 * textual representation that reflects the values used to derive the score. 
 * The Base group represents the intrinsic qualities of a vulnerability. The 
 * Temporal group reflects the characteristics of a vulnerability that change 
 * over time. The Environmental group represents the characteristics of a 
 * vulnerability that are unique to any user's environment. CVSS enables IT 
 * managers, vulnerability bulletin providers, security vendors, application 
 * vendors and researchers to all benefit by adopting this common language of 
 * scoring IT vulnerabilities.
 * 
 * ----------------------------------------------------------------------------
 *                               DISCLAIMER
 * ----------------------------------------------------------------------------
 * This Java library implements the structure of the CVSS v2 standard. All the 
 * relevant information and texts are taken from the NIST documentation 
 * (https://nvd.nist.gov/cvss.cfm) or the FIRST CVSS guide
 * (http://www.first.org/cvss/).
 *
 * ----------------------------------------------------------------------------
 *                                 LICENSE
 * ----------------------------------------------------------------------------
 * The following project is released under BSD 3-Clause License
 *
 * Copyright (c) 2015 - Mattia Zago 
 * <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its 
 *    contributors may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
package it.zagomattia.cvss.base;

import it.zagomattia.cvss.CVSSVector;
import javax.swing.DefaultListModel;
import javax.swing.ListModel;

/**
 * This metric measures the number of times an attacker must authenticate to a 
 * in order to exploit a vulnerability. This metric does not gauge the 
 * strength or complexity of the authentication process, only that an attacker 
 * is required to provide credentials before an exploit may occur. 
 * The possible values for this metric are listed at 
 * <a href="http://www.first.org/cvss/cvss-guide.html">
 * http://www.first.org/cvss/cvss-guide.html</a>. 
 * The fewer authentication instances that are required, the higher 
 * the vulnerability score.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum AU implements CVSSVector {
    /**
     * Exploiting the vulnerability requires that the attacker authenticate 
     * two or more times, even if the same credentials are used each time. 
     * An example is an attacker authenticating to an operating system in 
     * addition to providing credentials to access an application hosted 
     * on that system.
     * <br>
     * The metric should be applied based on the authentication the attacker 
     * requires before launching an attack.  For example, if a mail server 
     * is vulnerable to a command that can be issued before a user 
     * authenticates, the metric should be scored as "None" because 
     * the attacker can launch the exploit before credentials are required.  
     * If the vulnerable command is only available after successful 
     * authentication, then the vulnerability should be scored as "Single" or 
     * "Multiple," depending on how many instances of authentication must 
     * occur before issuing the command.
     * <br>Value: 0.45
     */
    M(0.45),
    /**
     * The vulnerability requires an attacker to be logged into the system 
     * (such as at a command line or via a desktop session or web interface).
     * <br>Value: 0.56
     */
    S(0.56),
    /**
     * Authentication is not required to exploit the vulnerability.
     * <br>Value: 0.704
     */
    N(0.704);

    private final Double value;
    
    AU(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case M: return "M";
            case N: return "N";
            case S: return "S";
        }
        return null;
    }
    
    @Override
    public String getValueAsString() {
       return String.format("%1$,.3f", this.getValue());
    }
    
    public static ListModel getListModel() {
        DefaultListModel<AU> result = new DefaultListModel<>();
        
        result.addElement(AU.M);
        result.addElement(AU.N);
        result.addElement(AU.S);
        
        return result;
    }
}
