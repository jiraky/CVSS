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
package it.zagomattia.cvss.temporal;

import it.zagomattia.cvss.CVSSVector;

/**
 * This metric measures the current state of exploit techniques or code 
 * availability. Public availability of easy-to-use exploit code increases 
 * the number of potential attackers by including those who are unskilled, 
 * thereby increasing the severity of the vulnerability.
 * <br>
 * Initially, real-world exploitation may only be theoretical. Publication of 
 * proof of concept code, functional exploit code, or sufficient technical 
 * details necessary to exploit the vulnerability may follow. Furthermore, 
 * the exploit code available may progress from a proof-of-concept 
 * demonstration to exploit code that is successful in exploiting the 
 * vulnerability consistently. In severe cases, it may be delivered as the 
 * payload of a network-based worm or virus. The possible values for this 
 * metric are listed in Table 7. The more easily a vulnerability can be 
 * exploited, the higher the vulnerability score.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum E implements CVSSVector {
    /**
     * No exploit code is available, or an exploit is entirely theoretical.
     * <br>Value: 0.85
     */
    U(0.85),
    /**
     * Proof-of-concept exploit code or an attack demonstration that is not 
     * practical for most systems is available. The code or technique is not 
     * functional in all situations and may require substantial modification 
     * by a skilled attacker.
     * <br>Value: 0.9
     */
    POC(0.9),
    /**
     * Functional exploit code is available. The code works in most situations 
     * where the vulnerability exists.
     * <br>Value: 0.95
     */
    F(0.95),
    /**
     * Either the vulnerability is exploitable by functional mobile autonomous 
     * code, or no exploit is required (manual trigger) and details are widely 
     * available. The code works in every situation, or is actively being 
     * delivered via a mobile autonomous agent (such as a worm or virus).
     * <br>Value: 1.0
     */
    H(1.0),
    /**
     * Assigning this value to the metric will not influence the score. It 
     * is a signal to the equation to skip this metric.
     * <br>Value: 1.0
     */
    ND(1.0);
    
    private final Double value;
    
    E(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case U: return "U";
            case POC: return "POC";
            case H: return "H";
            case F: return "F";
            case ND: return "ND";
        }
        return null;
    }
    
    @Override
    public String getValueAsString() {
       return String.format("%1$,.3f", this.getValue());
    }
}
