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
 * This metric measures the complexity of the attack required to exploit the
 * vulnerability once an attacker has gained access to the target system. 
 * For example, consider a buffer overflow in an Internet service: once the 
 * target system is located, the attacker can launch an exploit at will.
 * <br>
 * Other vulnerabilities, however, may require additional steps in order to be 
 * exploited. For example, a vulnerability in an email client is only exploited 
 * after the user downloads and opens a tainted attachment. The possible values 
 * for this metric are listed at: 
 * <a href="http://www.first.org/cvss/cvss-guide.html">
 * http://www.first.org/cvss/cvss-guide.html</a>. The lower the required 
 * complexity, the higher the vulnerability score.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum AC implements CVSSVector {
    /**
     * Specialized access conditions exist. For example:
     * <ul>
     * <li>In most configurations, the attacking party must already have 
     * elevated privileges or spoof additional systems in addition to the 
     * attacking system (e.g., DNS hijacking).</li>
     * <li>The attack depends on social engineering methods that would be 
     * easily detected by knowledgeable people. For example, the victim must 
     * perform several suspicious or atypical actions.</li>
     * <li>The vulnerable configuration is seen very rarely in practice.</li>
     * <li>If a race condition exists, the window is very narrow.</li>
     * </ul>
     * <br>Value: 0.35
     */
    H(0.35),
    
    /**
     * The access conditions are somewhat specialized; the following are 
     * examples:
     * <ul>
     * <li>The attacking party is limited to a group of systems or users at 
     * some level of authorization, possibly untrusted.</li>
     * <li>Some information must be gathered before a successful attack 
     * can be launched.</li>
     * <li>The affected configuration is non-default, and is not commonly 
     * configured (e.g., a vulnerability present when a server performs user 
     * account authentication via a specific scheme, but not present for 
     * another authentication scheme).</li>
     * <li>The attack requires a small amount of social engineering that might 
     * occasionally fool cautious users (e.g., phishing attacks that modify a 
     * web browsers status bar to show a false link, having to be on someones 
     * buddy list before sending an IM exploit).</li>
     * </ul>
     * <br>Value: 0.61
     */
    M(0.61),
    
    /**
     * Specialized access conditions or extenuating circumstances do not 
     * exist. The following are examples:
     * <ul>
     * <li>The affected product typically requires access to a wide range of 
     * systems and users, possibly anonymous and untrusted 
     * (e.g., Internet-facing web or mail server).</li>
     * <li>The affected configuration is default or ubiquitous.</li>
     * <li>The attack can be performed manually and requires little 
     * skill or additional information gathering.</li>
     * <li>The race condition is a lazy one (i.e., it is technically a race 
     * but easily winnable).</li>
     * </ul>
     * <br>Value: 0.71
     */
    L(0.71);

    private final Double value;
    
    AC(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case H: return "H";
            case M: return "M";
            case L: return "L";
        }
        return null;
    }
    
    @Override
    public String getValueAsString() {
       return String.format("%1$,.3f", this.getValue());
    }
    
    public static ListModel getListModel() {
        DefaultListModel<AC> result = new DefaultListModel<>();
        
        result.addElement(AC.H);
        result.addElement(AC.L);
        result.addElement(AC.M);
        
        return result;
    }
    
}
