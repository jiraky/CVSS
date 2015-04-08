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
package it.zagomattia.cvss.environmental;

import it.zagomattia.cvss.CVSSVector;

/**
 * This metric measures the potential for loss of life or physical assets 
 * through damage or theft of property or equipment.  The metric may also 
 * measure economic loss of productivity or revenue. The possible values for 
 * this metric are listed in Table 10. Naturally, the greater the damage 
 * potential, the higher the vulnerability score.
 * <br>
 * Clearly, each organization must determine for themselves the precise 
 * meaning of "slight, moderate, significant, and catastrophic."
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum CDP implements CVSSVector {
    /**
     * There is no potential for loss of life, physical assets, productivity 
     * or revenue.
     * <br>Value: 0.0
     */
    N(0.0),
    /**
     * A successful exploit of this vulnerability may result in slight physical 
     * or property damage. Or, there may be a slight loss of revenue or 
     * productivity to the organization.
     * <br>Value: 0.1
     */
    L(0.1),
    /**
     * A successful exploit of this vulnerability may result in moderate 
     * physical or property damage. Or, there may be a moderate loss of 
     * revenue or productivity to the organization.
     * <br>Value: 0.3
     */
    LM(0.3),
    /**
     * A successful exploit of this vulnerability may result in significant 
     * physical or property damage or loss. Or, there may be a significant 
     * loss of revenue or productivity.
     * <br>Value: 0.4
     */
    MH(0.4),
    /**
     * A successful exploit of this vulnerability may result in catastrophic 
     * physical or property damage and loss. Or, there may be a catastrophic 
     * loss of revenue or productivity.
     * <br>Value: 0.5
     */
    H(0.5),
    /**
     * Assigning this value to the metric will not influence the score. 
     * It is a signal to the equation to skip this metric.
     * <br>Value: 0.0
     */
    ND(0.0);
    
    private final Double value;
    
    CDP(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case N: return "N";
            case L: return "L";
            case LM: return "LM";
            case MH: return "MH";
            case H: return "H";
            case ND: return "ND";
        }
        return null;
    }
    
    @Override
    public String getValueAsString() {
       return String.format("%1$,.3f", this.getValue());
    }
}
