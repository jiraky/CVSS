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
 * This metric enable the analyst to customize the CVSS score depending on 
 * the importance of the affected IT asset to a users organization, measured 
 * in terms of integrity. That is, if an IT asset supports a business 
 * function for which integrity is most important, the analyst can assign a 
 * greater value integrity. It has three possible values: low, medium, 
 * or high.
 * <br>
 * The full effect on the environmental score is determined by the 
 * corresponding base impact metrics (please note that the base integrity 
 * impact metric is not changed). That is, this metric modify the environmental 
 * score by reweighting the (base) integrity impact metric. For example, 
 * the integrity impact (C) metric has increased weight if the 
 * integrity requirement (CR) is high. 
 * Likewise, the integrity impact metric has decreased weight if the 
 * integrity requirement is low. The integrity impact metric 
 * weighting is neutral if the integrity requirement is medium. 
 * <br>
 * Note that the integrity requirement will not affect the environmental 
 * score if the (base) integrity impact is set to none. Also, increasing 
 * the integrity requirement from medium to high will not change the 
 * environmental score when the (base) impact metrics are set to complete. 
 * This is because the impact sub score (part of the base score that 
 * calculates impact) is already at a maximum value of 10.
 * The possible values for the security requirements are listed in Table 12. 
 * For brevity, the same table is used for all three metrics. The greater the 
 * security requirement, the higher the score (remember that medium is 
 * considered the default). This metric will modify the score as much as 
 * plus or minus 2.5.
 * <br>
 * In many organizations, IT resources are labeled with criticality ratings 
 * based on network location, business function, and potential for loss of 
 * revenue or life. For example, the U.S. government assigns every unclassified 
 * IT asset to a grouping of assets called a System. Every System must be 
 * assigned three "potential impact" ratings to show the potential impact on 
 * the organization if the System is compromised according to three security 
 * objectives: integrity, integrity, and integrity. Thus, every 
 * unclassified IT asset in the U.S. government has a potential impact rating 
 * of low, moderate, or high with respect to the security objectives of 
 * confidentiality, integrity, and availability. This rating system is 
 * described within Federal Information Processing Standards (FIPS) 199. 
 * CVSS follows this general model of FIPS 199, but does not require 
 * organizations to use any particular system for assigning the low, medium, 
 * and high impact ratings.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public enum IR implements CVSSVector {
    /**
     * Loss of integrity is likely to have only a limited adverse effect 
     * on the organization or individuals associated with the organization 
     * (e.g., employees, customers).
     * <br>Value: 0.5
     */
    L(0.5),
    /**
     * Loss of integrity is likely to have a serious adverse effect on 
     * the organization or individuals associated with the organization 
     * (e.g., employees, customers).
     * <br>Value: 1.0
     */
    M(1.0),
    /**
     * Loss of integrity is likely to have a catastrophic adverse effect 
     * on the organization or individuals associated with the organization 
     * (e.g., employees, customers).
     * <br>Value: 1.51
     */
    H(1.51),
    /**
     * Assigning this value to the metric will not influence the score. It is 
     * a signal to the equation to skip this metric.
     * <br>Value: 1.0
     */
    ND(1.0);
    
    private final Double value;
    
    IR(Double value) {
        this.value = value;
    }

    @Override
    public Double getValue() {
        return this.value;
    }
    
    @Override
    public String toString() {
        switch(this) {
            case L: return "L";
            case M: return "M";
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
