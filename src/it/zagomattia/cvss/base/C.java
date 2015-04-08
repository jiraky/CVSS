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

/**
 * This metric measures the impact on confidentiality of a successfully 
 * exploited vulnerability. Confidentiality refers to limiting information 
 * access and disclosure to only authorized users, as well as preventing 
 * access by, or disclosure to, unauthorized ones. The possible values for 
 * this metric are listed at 
 * <a href="http://www.first.org/cvss/cvss-guide.html">
 * http://www.first.org/cvss/cvss-guide.html</a>. Increased confidentiality 
 * impact increases the vulnerability score.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum C implements CVSSVector {
    /**
     * There is no impact to the confidentiality of the system.
     * <br>Value: 0.0
     */
    N(0.0),
    /**
     * There is considerable informational disclosure. Access to some system 
     * files is possible, but the attacker does not have control over what is 
     * obtained, or the scope of the loss is constrained. An example is a 
     * vulnerability that divulges only certain tables in a database.
     * <br>Value: 0.275
     */
    P(0.275),
    /**
     * There is total information disclosure, resulting in all system files 
     * being revealed. The attacker is able to read all of the system's data 
     * (memory, files, etc.)
     * <br>Value: 0.660
     */
    C(0.660);

    private final Double value;
    
    C(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case C: return "C";
            case N: return "N";
            case P: return "P";
        }
        return null;
    }
    
    @Override
    public String getValueAsString() {
       return String.format("%1$,.3f", this.getValue());
    }
}
