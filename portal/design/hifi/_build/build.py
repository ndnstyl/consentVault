#!/usr/bin/env python3
import p_overview,p_sources,p_evidence,p_deliveries,p_policies,p_components
from lib import page
page('index.html','Overview','Overview',p_overview.states())
page('sources-credentials.html','Sources and credentials','Capture sources',p_sources.states())
page('evidence.html','Evidence lookup','Evidence lookup',p_evidence.states())
page('deliveries.html','Connected systems and deliveries','Connected systems',p_deliveries.states())
page('policies.html','Policies','Policies',p_policies.states())
page('components.html','Component sheet','Components',p_components.build())
print('built')
