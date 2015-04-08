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

import it.zagomattia.cvss.CVSSMetric;

/**
 *
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public class CVSSBase implements CVSSMetric {
    private AV AccessVector;
    private AC AccessComplexity;
    private AU Authentication;
    private C ConfImpact;
    private I IntegImpact;
    private A AvailImpact;

    public CVSSBase() {
        
    }
    
    public CVSSBase(AV AccessVector, AC AccessComplexity, AU Authentication, 
                C ConfImpact, I IntegImpact, A AvailImpact) {
        setAccessVector(AccessVector);
        setAccessComplexity(AccessComplexity);
        setAuthentication(Authentication);
        setConfImpact(ConfImpact);
        setIntegImpact(IntegImpact);
        setAvailImpact(AvailImpact);
    }
    
    @Override
    public String toString() {
        return    "AV:"+getAccessVector()
                + "/AC:"+getAccessComplexity()
                + "/Au:"+getAuthentication()
                + "/C:"+getConfImpact()
                + "/I:"+getIntegImpact()
                + "/A:"+getAvailImpact()
                + "";
    }
    
    @Override
    public String toStringFull() {
        return toString();
    }
    
    @Override
    public boolean equals(Object target) {
        if( !(target instanceof CVSSBase)) return false;
        CVSSBase t = (CVSSBase)target;
        System.out.println(this);
        System.out.println(t);
        if(this.getAccessComplexity().equals(t.getAccessComplexity()))
            if(this.getAccessVector().equals(t.getAccessVector()))
                if(this.getAuthentication().equals(t.getAuthentication()))
                    if(this.getAvailImpact().equals(t.getAvailImpact()))
                        if(this.getConfImpact().equals(t.getConfImpact()))
                            if(this.getIntegImpact().equals(t.getIntegImpact()))
                                return true;
        
        return false;
    }
    
    @Override
    public String[] getVectors() {
        return new String[]{"AV","AC","Au","C","I","A"};
    }

    @Override
    public Double score() {
        return  Math.round (
                    10 * // need to round to 1 decimal digit
                    (
                        (0.6*impact()) + 
                        (0.4*exploitability()) - 
                        1.5
                    ) * 
                    f(impact())
                ) / 10d // need to round to 1 decimal digit
                ;
    }

    private double impact() {
        return  10.41 * (
                        1 - 
                            (1 - getConfImpact().getValue()) * 
                            (1 - getIntegImpact().getValue()) * 
                            (1 - getAvailImpact().getValue())
                        );
    }

    private double exploitability() {
        return  20 * 
                getAccessVector().getValue() * 
                getAccessComplexity().getValue() * 
                getAuthentication().getValue();
    }

    private double f(double impact) {
        if(impact == 0) return 0d;
        else return 1.176;
    }

    public AV getAccessVector() {
        return AccessVector;
    }

    public final void setAccessVector(AV AccessVector) {
        this.AccessVector = AccessVector;
    }

    public AC getAccessComplexity() {
        return AccessComplexity;
    }

    public final void setAccessComplexity(AC AccessComplexity) {
        this.AccessComplexity = AccessComplexity;
    }

    public AU getAuthentication() {
        return Authentication;
    }

    public final void setAuthentication(AU Authentication) {
        this.Authentication = Authentication;
    }

    public C getConfImpact() {
        return ConfImpact;
    }

    public final void setConfImpact(C ConfImpact) {
        this.ConfImpact = ConfImpact;
    }

    public I getIntegImpact() {
        return IntegImpact;
    }

    public final void setIntegImpact(I IntegImpact) {
        this.IntegImpact = IntegImpact;
    }

    public A getAvailImpact() {
        return AvailImpact;
    }

    public final void setAvailImpact(A AvailImpact) {
        this.AvailImpact = AvailImpact;
    }

    
}
