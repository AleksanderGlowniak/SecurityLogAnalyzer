package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.Incident;

import java.util.List;

public interface Detector {

    List<Incident> detect(List<Event> events);

}