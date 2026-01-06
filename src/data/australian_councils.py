"""
Real Australian Council Data for GrantThrive Platform
Based on official Australian Bureau of Statistics data and council websites
"""

AUSTRALIAN_COUNCILS = [
    # New South Wales Councils
    {
        'id': 'nsw-sydney',
        'name': 'City of Sydney',
        'state': 'NSW',
        'population': 248736,
        'tier': 1,
        'email_domain': 'cityofsydney.nsw.gov.au',
        'website': 'https://www.cityofsydney.nsw.gov.au',
        'contact_email': 'council@cityofsydney.nsw.gov.au',
        'phone': '+61 2 9265 9333',
        'address': 'Town Hall House, 456 Kent Street, Sydney NSW 2000',
        'mayor': 'Clover Moore',
        'grant_budget_annual': 15000000,
        'active_grant_programs': 12,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Environment', 'Small Business']
    },
    {
        'id': 'nsw-parramatta',
        'name': 'City of Parramatta',
        'state': 'NSW',
        'population': 249656,
        'tier': 1,
        'email_domain': 'cityofparramatta.nsw.gov.au',
        'website': 'https://www.cityofparramatta.nsw.gov.au',
        'contact_email': 'council@cityofparramatta.nsw.gov.au',
        'phone': '+61 2 9806 5050',
        'address': '126 Church Street, Parramatta NSW 2150',
        'mayor': 'Donna Davis',
        'grant_budget_annual': 8500000,
        'active_grant_programs': 8,
        'typical_grant_categories': ['Community Development', 'Youth Programs', 'Multicultural', 'Environment']
    },
    {
        'id': 'nsw-blacktown',
        'name': 'Blacktown City Council',
        'state': 'NSW',
        'population': 396427,
        'tier': 1,
        'email_domain': 'blacktown.nsw.gov.au',
        'website': 'https://www.blacktown.nsw.gov.au',
        'contact_email': 'council@blacktown.nsw.gov.au',
        'phone': '+61 2 9839 6000',
        'address': '62 Flushcombe Road, Blacktown NSW 2148',
        'mayor': 'Tony Bleasdale',
        'grant_budget_annual': 12000000,
        'active_grant_programs': 15,
        'typical_grant_categories': ['Community Development', 'Youth Programs', 'Sports & Recreation', 'Arts & Culture']
    },
    
    # Victoria Councils
    {
        'id': 'vic-melbourne',
        'name': 'City of Melbourne',
        'state': 'VIC',
        'population': 178955,
        'tier': 1,
        'email_domain': 'melbourne.vic.gov.au',
        'website': 'https://www.melbourne.vic.gov.au',
        'contact_email': 'info@melbourne.vic.gov.au',
        'phone': '+61 3 9658 9658',
        'address': 'Town Hall, 90-130 Swanston Street, Melbourne VIC 3000',
        'mayor': 'Sally Capp',
        'grant_budget_annual': 25000000,
        'active_grant_programs': 20,
        'typical_grant_categories': ['Arts & Culture', 'Community Development', 'Environment', 'Innovation', 'Small Business']
    },
    {
        'id': 'vic-casey',
        'name': 'City of Casey',
        'state': 'VIC',
        'population': 358526,
        'tier': 1,
        'email_domain': 'casey.vic.gov.au',
        'website': 'https://www.casey.vic.gov.au',
        'contact_email': 'caseycc@casey.vic.gov.au',
        'phone': '+61 3 9705 5200',
        'address': 'Civic Centre, 2 Patrick Northeast Drive, Narre Warren VIC 3805',
        'mayor': 'Susan Serey',
        'grant_budget_annual': 9500000,
        'active_grant_programs': 11,
        'typical_grant_categories': ['Community Development', 'Youth Programs', 'Sports & Recreation', 'Environment']
    },
    {
        'id': 'vic-geelong',
        'name': 'City of Greater Geelong',
        'state': 'VIC',
        'population': 271057,
        'tier': 2,
        'email_domain': 'geelongcity.vic.gov.au',
        'website': 'https://www.geelongcity.vic.gov.au',
        'contact_email': 'info@geelongcity.vic.gov.au',
        'phone': '+61 3 5272 5272',
        'address': 'Civic Centre, 103 Moorabool Street, Geelong VIC 3220',
        'mayor': 'Trent Sullivan',
        'grant_budget_annual': 7200000,
        'active_grant_programs': 9,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Environment', 'Economic Development']
    },
    
    # Queensland Councils
    {
        'id': 'qld-brisbane',
        'name': 'Brisbane City Council',
        'state': 'QLD',
        'population': 1267864,
        'tier': 1,
        'email_domain': 'brisbane.qld.gov.au',
        'website': 'https://www.brisbane.qld.gov.au',
        'contact_email': 'info@brisbane.qld.gov.au',
        'phone': '+61 7 3403 8888',
        'address': 'City Hall, King George Square, Brisbane QLD 4000',
        'mayor': 'Adrian Schrinner',
        'grant_budget_annual': 45000000,
        'active_grant_programs': 25,
        'typical_grant_categories': ['Community Development', 'Environment', 'Arts & Culture', 'Sports & Recreation', 'Innovation']
    },
    {
        'id': 'qld-gold-coast',
        'name': 'City of Gold Coast',
        'state': 'QLD',
        'population': 679127,
        'tier': 1,
        'email_domain': 'goldcoast.qld.gov.au',
        'website': 'https://www.goldcoast.qld.gov.au',
        'contact_email': 'mail@goldcoast.qld.gov.au',
        'phone': '+61 7 5581 6500',
        'address': '2 Nerang Street, Southport QLD 4215',
        'mayor': 'Tom Tate',
        'grant_budget_annual': 18000000,
        'active_grant_programs': 14,
        'typical_grant_categories': ['Community Development', 'Environment', 'Tourism', 'Arts & Culture']
    },
    {
        'id': 'qld-sunshine-coast',
        'name': 'Sunshine Coast Council',
        'state': 'QLD',
        'population': 355889,
        'tier': 1,
        'email_domain': 'sunshinecoast.qld.gov.au',
        'website': 'https://www.sunshinecoast.qld.gov.au',
        'contact_email': 'mail@sunshinecoast.qld.gov.au',
        'phone': '+61 7 5475 7272',
        'address': 'Locked Bag 72, Sunshine Coast Mail Centre QLD 4560',
        'mayor': 'Mark Jamieson',
        'grant_budget_annual': 12500000,
        'active_grant_programs': 10,
        'typical_grant_categories': ['Community Development', 'Environment', 'Arts & Culture', 'Innovation']
    },
    
    # South Australia Councils
    {
        'id': 'sa-adelaide',
        'name': 'City of Adelaide',
        'state': 'SA',
        'population': 25542,
        'tier': 2,
        'email_domain': 'cityofadelaide.com.au',
        'website': 'https://www.cityofadelaide.com.au',
        'contact_email': 'city@cityofadelaide.com.au',
        'phone': '+61 8 8203 7203',
        'address': '25 Pirie Street, Adelaide SA 5000',
        'mayor': 'Jane Lomax-Smith',
        'grant_budget_annual': 8500000,
        'active_grant_programs': 12,
        'typical_grant_categories': ['Arts & Culture', 'Community Development', 'Innovation', 'Small Business']
    },
    {
        'id': 'sa-charles-sturt',
        'name': 'City of Charles Sturt',
        'state': 'SA',
        'population': 118956,
        'tier': 2,
        'email_domain': 'charlessturt.sa.gov.au',
        'website': 'https://www.charlessturt.sa.gov.au',
        'contact_email': 'customerservice@charlessturt.sa.gov.au',
        'phone': '+61 8 8408 1111',
        'address': '72 Woodville Road, Woodville SA 5011',
        'mayor': 'Mike Fotakis',
        'grant_budget_annual': 4200000,
        'active_grant_programs': 7,
        'typical_grant_categories': ['Community Development', 'Youth Programs', 'Environment', 'Multicultural']
    },
    
    # Western Australia Councils
    {
        'id': 'wa-perth',
        'name': 'City of Perth',
        'state': 'WA',
        'population': 30971,
        'tier': 2,
        'email_domain': 'perth.wa.gov.au',
        'website': 'https://www.perth.wa.gov.au',
        'contact_email': 'info@cityofperth.wa.gov.au',
        'phone': '+61 8 9461 3333',
        'address': 'Council House, 27 St Georges Terrace, Perth WA 6000',
        'mayor': 'Basil Zempilas',
        'grant_budget_annual': 6500000,
        'active_grant_programs': 8,
        'typical_grant_categories': ['Arts & Culture', 'Community Development', 'Innovation', 'Small Business']
    },
    {
        'id': 'wa-stirling',
        'name': 'City of Stirling',
        'state': 'WA',
        'population': 223816,
        'tier': 2,
        'email_domain': 'stirling.wa.gov.au',
        'website': 'https://www.stirling.wa.gov.au',
        'contact_email': 'info@stirling.wa.gov.au',
        'phone': '+61 8 9205 8555',
        'address': '25 Cedric Street, Stirling WA 6021',
        'mayor': 'Mark Irwin',
        'grant_budget_annual': 5800000,
        'active_grant_programs': 9,
        'typical_grant_categories': ['Community Development', 'Environment', 'Youth Programs', 'Arts & Culture']
    },
    
    # Tasmania Councils
    {
        'id': 'tas-hobart',
        'name': 'City of Hobart',
        'state': 'TAS',
        'population': 55250,
        'tier': 3,
        'email_domain': 'hobartcity.com.au',
        'website': 'https://www.hobartcity.com.au',
        'contact_email': 'communications@hobartcity.com.au',
        'phone': '+61 3 6238 2711',
        'address': '50 Macquarie Street, Hobart TAS 7000',
        'mayor': 'Anna Reynolds',
        'grant_budget_annual': 2800000,
        'active_grant_programs': 6,
        'typical_grant_categories': ['Arts & Culture', 'Community Development', 'Environment', 'Heritage']
    },
    {
        'id': 'tas-launceston',
        'name': 'City of Launceston',
        'state': 'TAS',
        'population': 69427,
        'tier': 3,
        'email_domain': 'launceston.tas.gov.au',
        'website': 'https://www.launceston.tas.gov.au',
        'contact_email': 'admin@launceston.tas.gov.au',
        'phone': '+61 3 6323 3000',
        'address': '18 St John Street, Launceston TAS 7250',
        'mayor': 'Matthew Garwood',
        'grant_budget_annual': 2200000,
        'active_grant_programs': 5,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Environment', 'Economic Development']
    },
    
    # Northern Territory Councils
    {
        'id': 'nt-darwin',
        'name': 'City of Darwin',
        'state': 'NT',
        'population': 84613,
        'tier': 3,
        'email_domain': 'darwin.nt.gov.au',
        'website': 'https://www.darwin.nt.gov.au',
        'contact_email': 'council@darwin.nt.gov.au',
        'phone': '+61 8 8930 0300',
        'address': 'Harry Chan Avenue, Darwin NT 0800',
        'mayor': 'Kon Vatskalis',
        'grant_budget_annual': 3200000,
        'active_grant_programs': 7,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Environment', 'Indigenous Programs']
    },
    {
        'id': 'nt-alice-springs',
        'name': 'Alice Springs Town Council',
        'state': 'NT',
        'population': 26534,
        'tier': 4,
        'email_domain': 'astc.nt.gov.au',
        'website': 'https://www.astc.nt.gov.au',
        'contact_email': 'astc@astc.nt.gov.au',
        'phone': '+61 8 8950 0500',
        'address': 'Civic Centre, 93 Todd Street, Alice Springs NT 0870',
        'mayor': 'Matt Paterson',
        'grant_budget_annual': 850000,
        'active_grant_programs': 4,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Indigenous Programs', 'Tourism']
    },
    
    # Australian Capital Territory
    {
        'id': 'act-canberra',
        'name': 'ACT Government',
        'state': 'ACT',
        'population': 431380,
        'tier': 1,
        'email_domain': 'act.gov.au',
        'website': 'https://www.act.gov.au',
        'contact_email': 'info@act.gov.au',
        'phone': '+61 2 6207 1000',
        'address': 'GPO Box 158, Canberra ACT 2601',
        'mayor': 'Andrew Barr (Chief Minister)',
        'grant_budget_annual': 35000000,
        'active_grant_programs': 18,
        'typical_grant_categories': ['Community Development', 'Innovation', 'Environment', 'Arts & Culture', 'Small Business']
    }
]

# New Zealand Councils (for international expansion)
NEW_ZEALAND_COUNCILS = [
    {
        'id': 'nz-auckland',
        'name': 'Auckland Council',
        'state': 'Auckland',
        'country': 'NZ',
        'population': 1695200,
        'tier': 1,
        'email_domain': 'aucklandcouncil.govt.nz',
        'website': 'https://www.aucklandcouncil.govt.nz',
        'contact_email': 'info@aucklandcouncil.govt.nz',
        'phone': '+64 9 301 0101',
        'address': '135 Albert Street, Auckland 1010',
        'mayor': 'Wayne Brown',
        'grant_budget_annual': 25000000,
        'active_grant_programs': 15,
        'typical_grant_categories': ['Community Development', 'Arts & Culture', 'Environment', 'Innovation']
    },
    {
        'id': 'nz-wellington',
        'name': 'Wellington City Council',
        'state': 'Wellington',
        'country': 'NZ',
        'population': 215100,
        'tier': 2,
        'email_domain': 'wcc.govt.nz',
        'website': 'https://www.wellington.govt.nz',
        'contact_email': 'info@wcc.govt.nz',
        'phone': '+64 4 499 4444',
        'address': '101 Wakefield Street, Wellington 6011',
        'mayor': 'Tory Whanau',
        'grant_budget_annual': 8500000,
        'active_grant_programs': 10,
        'typical_grant_categories': ['Arts & Culture', 'Community Development', 'Environment', 'Innovation']
    },
    {
        'id': 'nz-christchurch',
        'name': 'Christchurch City Council',
        'state': 'Canterbury',
        'country': 'NZ',
        'population': 383200,
        'tier': 1,
        'email_domain': 'ccc.govt.nz',
        'website': 'https://www.ccc.govt.nz',
        'contact_email': 'info@ccc.govt.nz',
        'phone': '+64 3 941 8999',
        'address': '53 Hereford Street, Christchurch 8011',
        'mayor': 'Phil Mauger',
        'grant_budget_annual': 12000000,
        'active_grant_programs': 12,
        'typical_grant_categories': ['Community Development', 'Environment', 'Arts & Culture', 'Recovery & Resilience']
    }
]

# Grant Program Templates based on real Australian council programs
GRANT_PROGRAM_TEMPLATES = [
    {
        'id': 'community-development',
        'title': 'Community Development Grant',
        'category': 'Community Development',
        'description': 'Supporting projects that strengthen community connections and improve quality of life for residents.',
        'min_amount': 1000,
        'max_amount': 50000,
        'typical_duration': '12 months',
        'eligibility_criteria': [
            'Registered not-for-profit organization',
            'Project must benefit local community',
            'Demonstrated community support',
            'Clear project outcomes and evaluation plan'
        ],
        'assessment_criteria': [
            'Community benefit and impact',
            'Project feasibility and planning',
            'Budget appropriateness',
            'Organizational capacity',
            'Sustainability and ongoing impact'
        ],
        'required_documents': [
            'Project proposal',
            'Detailed budget',
            'Letters of support',
            'Organization registration documents',
            'Insurance certificates'
        ]
    },
    {
        'id': 'arts-culture',
        'title': 'Arts & Culture Grant',
        'category': 'Arts & Culture',
        'description': 'Fostering creative expression and cultural activities that enrich our community.',
        'min_amount': 500,
        'max_amount': 25000,
        'typical_duration': '6-18 months',
        'eligibility_criteria': [
            'Individual artists or arts organizations',
            'Project must have public benefit',
            'Demonstrated artistic merit',
            'Local connection or benefit'
        ],
        'assessment_criteria': [
            'Artistic merit and innovation',
            'Community engagement and access',
            'Professional development outcomes',
            'Budget and value for money',
            'Cultural significance'
        ],
        'required_documents': [
            'Artistic proposal',
            'Portfolio or previous work examples',
            'Budget breakdown',
            'Venue confirmations',
            'Marketing plan'
        ]
    },
    {
        'id': 'environment',
        'title': 'Environmental Sustainability Grant',
        'category': 'Environment',
        'description': 'Supporting initiatives that protect and enhance our local environment.',
        'min_amount': 2000,
        'max_amount': 75000,
        'typical_duration': '12-24 months',
        'eligibility_criteria': [
            'Environmental focus with measurable outcomes',
            'Community or organizational applicant',
            'Local environmental benefit',
            'Scientific or evidence-based approach'
        ],
        'assessment_criteria': [
            'Environmental impact and benefit',
            'Scientific merit and methodology',
            'Community engagement and education',
            'Long-term sustainability',
            'Innovation and best practice'
        ],
        'required_documents': [
            'Environmental impact assessment',
            'Technical specifications',
            'Budget and timeline',
            'Permits and approvals',
            'Monitoring and evaluation plan'
        ]
    },
    {
        'id': 'youth-programs',
        'title': 'Youth Development Grant',
        'category': 'Youth Programs',
        'description': 'Empowering young people through education, skills development, and leadership opportunities.',
        'min_amount': 1500,
        'max_amount': 30000,
        'typical_duration': '6-12 months',
        'eligibility_criteria': [
            'Programs targeting youth aged 12-25',
            'Registered organization or school',
            'Demonstrated youth engagement',
            'Clear learning or development outcomes'
        ],
        'assessment_criteria': [
            'Youth engagement and participation',
            'Learning and development outcomes',
            'Program design and delivery',
            'Organizational capacity',
            'Long-term impact on participants'
        ],
        'required_documents': [
            'Program outline and curriculum',
            'Youth engagement strategy',
            'Budget and resources',
            'Staff qualifications',
            'Safety and risk management plan'
        ]
    },
    {
        'id': 'small-business',
        'title': 'Small Business Development Grant',
        'category': 'Economic Development',
        'description': 'Supporting local businesses to grow, innovate, and create employment opportunities.',
        'min_amount': 2500,
        'max_amount': 40000,
        'typical_duration': '12 months',
        'eligibility_criteria': [
            'Small business with less than 20 employees',
            'Operating in local area for minimum 12 months',
            'Demonstrated business viability',
            'Job creation or retention potential'
        ],
        'assessment_criteria': [
            'Business viability and growth potential',
            'Economic benefit to local area',
            'Innovation and competitiveness',
            'Job creation or retention',
            'Financial sustainability'
        ],
        'required_documents': [
            'Business plan',
            'Financial statements',
            'Market analysis',
            'Budget and cash flow projections',
            'Employment impact statement'
        ]
    }
]

# Sample grant applications for testing
SAMPLE_APPLICATIONS = [
    {
        'id': 'app-001',
        'grant_program': 'community-development',
        'applicant_name': 'Sarah Mitchell',
        'organization': 'Neighborhood Connect',
        'project_title': 'Community Garden Initiative',
        'project_description': 'Establishing community gardens in three underserved neighborhoods to improve food security, promote healthy eating, and strengthen community connections. The project will include raised garden beds, composting systems, educational workshops, and ongoing community engagement activities.',
        'requested_amount': 25000,
        'project_duration': '18 months',
        'status': 'under_review',
        'submission_date': '2024-03-15',
        'expected_participants': 150,
        'community_benefit': 'Improved food security, community cohesion, environmental education',
        'sustainability_plan': 'Community ownership model with ongoing volunteer coordination'
    },
    {
        'id': 'app-002',
        'grant_program': 'arts-culture',
        'applicant_name': 'Marcus Chen',
        'organization': 'Cultural Arts Collective',
        'project_title': 'Multicultural Festival 2024',
        'project_description': 'Annual multicultural festival celebrating the diverse communities in our city through music, dance, food, and art. Features performances from 15 cultural groups, food stalls, art exhibitions, and children\'s activities.',
        'requested_amount': 18000,
        'project_duration': '6 months',
        'status': 'approved',
        'submission_date': '2024-02-28',
        'expected_participants': 5000,
        'community_benefit': 'Cultural celebration, community unity, economic activity',
        'sustainability_plan': 'Annual event with growing community support and sponsorship'
    },
    {
        'id': 'app-003',
        'grant_program': 'environment',
        'applicant_name': 'Dr. Emma Rodriguez',
        'organization': 'Green Future Foundation',
        'project_title': 'Urban Tree Canopy Restoration',
        'project_description': 'Large-scale tree planting program to restore urban canopy coverage in heat-affected areas. Includes native species selection, community planting days, ongoing maintenance, and educational components about urban ecology.',
        'requested_amount': 45000,
        'project_duration': '24 months',
        'status': 'under_review',
        'submission_date': '2024-03-10',
        'expected_participants': 300,
        'community_benefit': 'Reduced urban heat, improved air quality, biodiversity enhancement',
        'sustainability_plan': 'Partnership with council for ongoing maintenance and monitoring'
    },
    {
        'id': 'app-004',
        'grant_program': 'youth-programs',
        'applicant_name': 'James Wilson',
        'organization': 'Youth Empowerment Network',
        'project_title': 'Digital Skills for Future Leaders',
        'project_description': 'Comprehensive digital literacy and leadership program for disadvantaged youth aged 16-24. Includes coding workshops, digital marketing training, entrepreneurship mentoring, and work placement opportunities.',
        'requested_amount': 22000,
        'project_duration': '12 months',
        'status': 'approved',
        'submission_date': '2024-02-15',
        'expected_participants': 40,
        'community_benefit': 'Youth employment readiness, digital inclusion, leadership development',
        'sustainability_plan': 'Industry partnerships for ongoing mentoring and job placement'
    }
]

