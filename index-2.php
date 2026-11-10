<?php

/*
|--------------------------------------------------------------------------
| AYK WEBSITE FORM PROCESSING
|--------------------------------------------------------------------------
| All POST/AJAX processing happens before <!DOCTYPE html>.
| This prevents "headers already sent" errors and allows clean JSON
| responses from the manpower form.
|--------------------------------------------------------------------------
*/

/* ---------------------------------------------------------
   Lightweight HTML compression for text responses.
   Images/CSS/JS assets are handled separately by the browser.
   --------------------------------------------------------- */
if (
    !headers_sent()
    && function_exists('ob_gzhandler')
    && !ini_get('zlib.output_compression')
) {
    ob_start('ob_gzhandler');
}

/* =========================================================
   MANPOWER REQUIREMENT FORM
   ========================================================= */

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['manpower_submit'])
) {

    /*
     * Tell manpower-form.php that this request is being processed
     * from the top of index.php.
     *
     * It must process the submission and return JSON.
     * It must NOT render the normal manpower form.
     */
    if (!defined('MANPOWER_FORM_PROCESS_ONLY')) {
        define('MANPOWER_FORM_PROCESS_ONLY', true);
    }

    require_once __DIR__ . '/includes/manpower-form.php';

    /*
     * manpower-form.php should terminate the request itself
     * after returning its JSON response.
     */
    exit;
}

/* =========================================================
   VENDOR FORM
   ========================================================= */

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['form_type'])
    && $_POST['form_type'] === 'vendor'
) {

    /*
    |--------------------------------------------------------------------------
    | Detect AJAX request
    |--------------------------------------------------------------------------
    */

    $isAjax =
        isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';


    /*
    |--------------------------------------------------------------------------
    | Client IP
    |--------------------------------------------------------------------------
    */

    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';


    /*
    |--------------------------------------------------------------------------
    | Rate Limit Storage
    |--------------------------------------------------------------------------
    |
    | No database required.
    |
    | 3 successful submissions per IP per hour.
    | Also prevents submissions within 60 seconds of each other.
    |
    */

    $rateLimitDir = __DIR__ . '/storage/vendor-rate-limit';

    if (!is_dir($rateLimitDir)) {
        @mkdir($rateLimitDir, 0755, true);
    }

    $ipHash = hash('sha256', $clientIp);

    $rateFile = $rateLimitDir . '/' . $ipHash . '.json';

    $now = time();

    $rateData = [
        'attempts' => []
    ];


    /*
    |--------------------------------------------------------------------------
    | Read existing rate-limit data
    |--------------------------------------------------------------------------
    */

    if (is_file($rateFile)) {

        $stored = @file_get_contents($rateFile);

        if ($stored !== false) {

            $decoded = json_decode(
                $stored,
                true
            );

            if (is_array($decoded)) {
                $rateData = $decoded;
            }
        }
    }


    /*
    |--------------------------------------------------------------------------
    | Remove records older than 1 hour
    |--------------------------------------------------------------------------
    */

    $rateData['attempts'] = array_values(
        array_filter(
            $rateData['attempts'] ?? [],
            function ($timestamp) use ($now) {

                return
                    is_numeric($timestamp)
                    && (int)$timestamp > ($now - 3600);
            }
        )
    );


    /*
    |--------------------------------------------------------------------------
    | Maximum 3 successful submissions / hour
    |--------------------------------------------------------------------------
    */

    if (count($rateData['attempts']) >= 3) {

        if ($isAjax) {

            http_response_code(429);

            echo '
                <p style="color:red;">
                    Too many vendor requests from this network.
                    Please try again later.
                </p>
            ';

            exit;
        }

        http_response_code(429);

        exit(
            'Too many vendor requests. Please try again later.'
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Rapid submission protection
    |--------------------------------------------------------------------------
    */

    if (!empty($rateData['attempts'])) {

        $lastAttempt =
            (int)end($rateData['attempts']);

        if (($now - $lastAttempt) < 60) {

            $remaining =
                60 - ($now - $lastAttempt);

            if ($isAjax) {

                http_response_code(429);

                echo '
                    <p style="color:red;">
                        Please wait ' .
                        (int)$remaining .
                        ' seconds before submitting again.
                    </p>
                ';

                exit;
            }

            http_response_code(429);

            exit(
                'Please wait before submitting again.'
            );
        }
    }


    /*
    |--------------------------------------------------------------------------
    | Honeypot protection
    |--------------------------------------------------------------------------
    |
    | Normal visitors never see this field.
    | Simple bots often fill every field.
    |--------------------------------------------------------------------------
    */

    $honeypot =
        trim($_POST['website'] ?? '');

    if ($honeypot !== '') {

        /*
         * Do not tell the bot it was detected.
         */

        if ($isAjax) {

            echo '
                <p style="color:green;">
                    Vendor request submitted successfully.
                </p>
            ';

            exit;
        }

        exit;
    }


    /*
    |--------------------------------------------------------------------------
    | Get form values
    |--------------------------------------------------------------------------
    */

    $company =
        trim($_POST['company_name'] ?? '');

    $person =
        trim($_POST['contact_person'] ?? '');

    $email =
        trim($_POST['email'] ?? '');

    $country =
        trim($_POST['country'] ?? '');

    $message_text =
        trim($_POST['message'] ?? '');


    /*
    |--------------------------------------------------------------------------
    | Field length limits
    |--------------------------------------------------------------------------
    */

    if (
        mb_strlen($company) > 180 ||
        mb_strlen($person) > 120 ||
        mb_strlen($email) > 254 ||
        mb_strlen($country) > 100 ||
        mb_strlen($message_text) > 3000
    ) {

        if ($isAjax) {

            http_response_code(400);

            echo '
                <p style="color:red;">
                    One or more fields are too long.
                </p>
            ';

            exit;
        }

        $error = true;
    }


    /*
    |--------------------------------------------------------------------------
    | Required field validation
    |--------------------------------------------------------------------------
    */

    if (
        empty($company) ||
        empty($person) ||
        empty($country) ||
        !filter_var(
            $email,
            FILTER_VALIDATE_EMAIL
        )
    ) {

        if ($isAjax) {

            http_response_code(400);

            echo '
                <p style="color:red;">
                    Please complete all required fields correctly.
                </p>
            ';

            exit;
        }

        $error = true;
    }


    /*
    |--------------------------------------------------------------------------
    | Prevent email header injection
    |--------------------------------------------------------------------------
    */

    $safeEmail =
        str_replace(
            ["\r", "\n"],
            '',
            $email
        );


    /*
    |--------------------------------------------------------------------------
    | Additional email safety check
    |--------------------------------------------------------------------------
    */

    if (
        preg_match(
            '/[\r\n]/',
            $email
        )
    ) {

        if ($isAjax) {

            http_response_code(400);

            echo '
                <p style="color:red;">
                    Invalid email address.
                </p>
            ';

            exit;
        }

        $error = true;
    }


    /*
    |--------------------------------------------------------------------------
    | Send email
    |--------------------------------------------------------------------------
    */

    if (empty($error)) {

        $to =
            'info@ayk.global';


        $subject =
            'New Vendor Request - ' .
            $company;


        $message =
            "New Vendor Registration Request:\n\n";


        $message .=
            "Company Name: " .
            $company .
            "\n";


        $message .=
            "Contact Person: " .
            $person .
            "\n";


        $message .=
            "Email: " .
            $safeEmail .
            "\n";


        $message .=
            "Country: " .
            $country .
            "\n\n";


        $message .=
            "Message:\n" .
            $message_text .
            "\n";


        $headers =
            "From: AYK Website <no-reply@ayk.global>\r\n";


        $headers .=
            "Reply-To: " .
            $safeEmail .
            "\r\n";


        $headers .=
            "Content-Type: text/plain; charset=UTF-8\r\n";


        /*
        |--------------------------------------------------------------------------
        | Send
        |--------------------------------------------------------------------------
        */

        if (
            mail(
                $to,
                $subject,
                $message,
                $headers
            )
        ) {

            /*
             * Record successful submission.
             */

            $rateData['attempts'][] =
                $now;


            /*
             * Keep only the latest 3 records.
             */

            $rateData['attempts'] =
                array_slice(
                    $rateData['attempts'],
                    -3
                );


            @file_put_contents(
                $rateFile,
                json_encode(
                    $rateData,
                    JSON_UNESCAPED_UNICODE
                ),
                LOCK_EX
            );


            $success = true;

        } else {

            $error = true;
        }
    }


    /*
    |--------------------------------------------------------------------------
    | AJAX RESPONSE
    |--------------------------------------------------------------------------
    */

    if ($isAjax) {

        ob_start();
        ?>

        <form
            class="manpower-form"
            data-form-id="vendor"
        >

            <input
                type="hidden"
                name="form_type"
                value="vendor"
            >


            <!-- Honeypot -->
            <div
                style="
                    position:absolute;
                    left:-9999px;
                    top:-9999px;
                    width:1px;
                    height:1px;
                    overflow:hidden;
                "
                aria-hidden="true"
            >

                <label for="vendor-website">
                    Website
                </label>

                <input
                    type="text"
                    id="vendor-website"
                    name="website"
                    tabindex="-1"
                    autocomplete="off"
                >

            </div>


            <?php if (!empty($success)): ?>

                <p style="color:green;">
                    Vendor request submitted successfully.
                </p>

            <?php elseif (!empty($error)): ?>

                <p style="color:red;">
                    ❌ Something went wrong. Please try again.
                </p>

            <?php endif; ?>


            <input
                type="text"
                name="company_name"
                placeholder="Company Name"
                maxlength="180"
                required
            >


            <input
                type="text"
                name="contact_person"
                placeholder="Contact Person"
                maxlength="120"
                required
            >


            <input
                type="email"
                name="email"
                placeholder="Email Address"
                maxlength="254"
                required
            >


            <input
                type="text"
                name="country"
                placeholder="Country"
                maxlength="100"
                required
            >


            <textarea
                name="message"
                placeholder="Tell us about your manpower requirements or vendor process"
                rows="3"
                maxlength="3000"
            ></textarea>


            <button type="submit">
                Register Us as Vendor
            </button>

        </form>

        <?php

        echo ob_get_clean();

        exit;
    }
}

?>
<!DOCTYPE html>
<html lang="en">

    <head>
        <meta charset="UTF-8">
        <link rel="icon" type="image/webp" href="/img/img/g-logos/main_logo.webp">
        <link rel="apple-touch-icon" href="/img/img/g-logos/main_logo.webp">
        <title>#1 Best Recruitment & HR Manpower Agency in Pakistan</title>
        <meta content="width=device-width, initial-scale=1.0" name="viewport">
        
        
        <link rel="preload" as="image" href="/img/homepage.webp" fetchpriority="high">
        <link rel="preconnect" href="https://cdnjs.cloudflare.com">
        <link rel="preconnect" href="https://cdn.jsdelivr.net">
        
        <meta name="description" content="#1 Best recruitment agency in Pakistan for overseas recruitment, skilled Pakistani manpower, HR staffing and workforce solutions across GCC and Europe.">
        <meta name="google-site-verification" content="rHQzQ1i6tJkWhFpwEAlXA0LoY7CTf0F0ynzEBz_HrfA" />
        <meta name='dmca-site-verification' content='elhVL3RLOWlmc1l5SXFRVElsZ1MxUT090' />
        <meta name="msvalidate.01" content="2DE78DCC5AEDFEA3A4C67D70FA3545E5" />

<meta name="keywords" content="
overseas recruitment agency in Pakistan,
Best overseas recruitment agency in Pakistan,
#1 overseas recruitment agency in Pakistan,
Best manpower agency in Pakistan,
Best manpower agency,
Best hr manpower agency,
top hr manpower agency,
top manpower agency,
best agency in pakistan,
manpower agency in Pakistan,
hr manpower agency in Pakistan,
overseas jobs for Pakistanis,
saudi arabia jobs,
UAE jobs,
Qatar jobs,
Kuwait jobs,
USA jobs,
Kazakhstan jobs,
Uzbekistan jobs,
Azerbaijan jobs,
Bahrain jobs,
Europe jobs,
South Korea jobs,
international employment agency,
foreign job consultancy,
South Korea work visa Pakistan,
USA work visa agency,
best hr manpower agency in pakistan for qatar,
best hr manpower agency in pakistan for bahrain,
best hr manpower agency in pakistan for Kazakhstan,
best hr manpower agency in pakistan for Uzbekistan,
best hr manpower agency in pakistan for Turkey,
best hr manpower agency in pakistan for Azerbaijan,
best hr manpower agency in pakistan for UK,
best hr manpower agency in pakistan for Belarus,
best hr manpower agency in pakistan for Europe,
best hr manpower agency in pakistan for Thailand,
best hr manpower agency in pakistan for South Korea,
Saudi Arabia jobs Pakistan,
best hr manpower agency in pakistan for UAE,
best hr manpower agency in pakistan for Dubai,
South Korea manpower agency,
USA manpower agency,
Qatar manpower agency,
Bahrain manpower agency,
Kazakhstan manpower agency,
Uzbekistan manpower agency,
Turkey manpower agency,
Azerbaijan manpower agency,
UK manpower agency,
Belarus manpower agency,
Europe manpower agency,
Thailand manpower agency,
Saudi Arabia manpower agency,
Kuwait manpower agency,
AYK Overseas Recruitment & HR Manpower Agency,
AYK Overseas Recruitment & HR Manpower Agency Recruitment
AYK Overseas Recruitment & HR Manpower Agency 
">

<script>
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', 'G-VEZBBED4FL');
</script>


        
<link rel="canonical" href="https://ayk.global/">

<meta name="robots" content="index, follow">



<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": ["Organization", "EmploymentAgency"],
      "@id": "https://ayk.global/#organization",
      "name": "AYK Overseas Recruitment & HR Manpower Agency",
      "url": "https://ayk.global/",
      "logo": "https://ayk.global/img/brand-logo.png",
      "image": "https://ayk.global/img/brand-logo.png",
      "telephone": "+92-21-34392918",
      "email": "info@ayk.global",
      "openingHours": "Mo-Su 09:00-21:00",
      "address": {
        "@type": "PostalAddress",
        "streetAddress": "Office No. 402, 4th Floor, Merium Heights, Baloch Colony, Near Maqbool Masjid, Kathiawar Society Block A, Bangalore Town, Shahra-e-Faisal",
        "addressLocality": "Karachi",
        "addressRegion": "Sindh",
        "postalCode": "75160",
        "addressCountry": "PK"
      },
      "contactPoint": {
        "@type": "ContactPoint",
        "contactType": "customer service",
        "telephone": "+92-21-34392918",
        "areaServed": "Worldwide",
        "availableLanguage": ["English", "Urdu"]
      },
      "areaServed": ["Saudi Arabia", "UAE", "Qatar", "Kuwait", "Oman", "Bahrain", "Europe", "Worldwide"],
      "sameAs": [
        "https://www.facebook.com/profile.php?id=61583766680943",
        "https://www.linkedin.com/company/ayk-overseas-recruitment-hr-manpower-agency/",
        "https://www.instagram.com/aykoverseas3/",
        "https://www.tiktok.com/@the.ayk.overseas"
      ]
    },
    {
      "@type": "EmploymentAgency",
      "@id": "https://ayk.global/#islamabad-office",
      "name": "AYK Overseas Recruitment & HR Manpower Agency - Islamabad Office",
      "url": "https://ayk.global/",
      "image": "https://ayk.global/img/brand-logo.png",
      "parentOrganization": { "@id": "https://ayk.global/#organization" },
      "telephone": "+92-51-2769919",
      "email": "info@ayk.global",
      "openingHours": "Mo-Su 09:00-21:00",
      "address": {
        "@type": "PostalAddress",
        "streetAddress": "Office No 04, 3rd Floor, Capitol Plaza, G11 Markaz",
        "addressLocality": "Islamabad",
        "addressRegion": "Islamabad Capital Territory",
        "addressCountry": "PK"
      }
    },
    {
      "@type": "WebSite",
      "@id": "https://ayk.global/#website",
      "url": "https://ayk.global/",
      "name": "AYK Overseas",
      "publisher": { "@id": "https://ayk.global/#organization" }
    },
    {
      "@type": "Service",
      "@id": "https://ayk.global/#service",
      "serviceType": "Overseas Recruitment & Manpower Supply",
      "provider": { "@id": "https://ayk.global/#organization" },
      "areaServed": { "@type": "Place", "name": "Worldwide" },
      "description": "#1 Best recruitment agency in Pakistan for overseas recruitment, skilled Pakistani manpower, HR staffing and workforce solutions across GCC and Europe."
    }
  ]
}
</script>

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "How Can Employers Hire Manpower from Pakistan?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "You can share your manpower requirements with us via our website, email, or WhatsApp. Once received, we begin sourcing and provide shortlisted candidates for your review."
      }
    },
    {
      "@type": "Question",
      "name": "Do You Provide Bulk Manpower Recruitment for Large Projects?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, we specialize in bulk hiring and can efficiently supply manpower for small to large-scale projects across various industries."
      }
    },
    {
      "@type": "Question",
      "name": "Which Industries Does Your Manpower Recruitment Agency Serve?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "We provide manpower recruitment services from Pakistan for construction workers, oil and gas, medical staff, facility management, IT, manufacturing, logistics and engineering sectors."
      }
    },
    {
      "@type": "Question",
      "name": "Are Pakistani Workers Pre-Screened, Verified & Trade-Tested?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, candidates are screened according to the employer's requirements, with trade testing arranged where required."
      }
    },
    {
      "@type": "Question",
      "name": "What Is Your Overseas Recruitment Process?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Our process includes requirement analysis, candidate sourcing, screening, shortlisting, interviews, documentation, visa processing, and deployment."
      }
    },
    {
      "@type": "Question",
      "name": "How Long Does It Take to Deploy Workers?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Timelines depend on the destination country, job category, documentation and visa approvals. We share a project-specific timeline after receiving your requirement."
      }
    },
    {
      "@type": "Question",
      "name": "Are You a Licensed Recruitment Agency?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, we are a government licensed overseas recruitment agency in Pakistan and fully compliant with international recruitment standards."
      }
    },
    {
      "@type": "Question",
      "name": "Do You Handle Visa and Documentation?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, we provide complete support including visa processing, documentation, medical tests, attestation, and travel coordination."
      }
    },
    {
      "@type": "Question",
      "name": "Can You Become Our Official Recruitment Vendor?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, we are open for vendor registration and long-term partnerships. We can follow your onboarding and compliance process."
      }
    },
    {
      "@type": "Question",
      "name": "What if a Worker Does Not Perform Well?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "We offer a replacement guarantee as per agreement to ensure your satisfaction and smooth project execution."
      }
    },
    
    {
      "@type": "Question",
      "name": "What Are the Costs Involved in Hiring?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Costs depend on job category, volume, and employer requirements. We provide transparent pricing after understanding your needs."
      }
    },
    {
      "@type": "Question",
      "name": "How Do We Get Started?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Simply contact us or submit your manpower request. Our team will guide you and start the recruitment process immediately."
      }
    }
  ]
}
</script>


<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebSite",
  "name": "AYK Overseas Recruitment & HR Manpower Agency",
  "url": "https://ayk.global/"
}
</script>

<meta property="og:title" content="#1 Best Recruitment & HR Manpower Agency in Pakistan">
<meta property="og:description" content="#1 Best recruitment agency in Pakistan for overseas recruitment, skilled Pakistani manpower, HR staffing and workforce solutions across GCC and Europe.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://ayk.global/">
<meta property="og:image" content="https://ayk.global/img/brand-logo.png">
<meta property="og:site_name" content="AYK Overseas">
 

<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="#1 Best Recruitment & HR Manpower Agency in Pakistan">
<meta name="twitter:description" content="#1 Best recruitment agency in Pakistan for overseas recruitment, skilled Pakistani manpower, HR staffing and workforce solutions across GCC and Europe.">
<meta name="twitter:image" content="https://ayk.global/img/brand-logo.png">

  
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>


<link rel="preload" as="style"
href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap"
onload="this.onload=null;this.rel='stylesheet'">

<noscript>
<link rel="stylesheet"
href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap">
</noscript>





<link rel="preload" as="style"
href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"
onload="this.onload=null;this.rel='stylesheet'">

<noscript>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link href="https://cdn.jsdelivr.net/npm/select2@4.1.0/dist/css/select2.min.css" rel="stylesheet" />
</noscript>

<link rel="preload"
      href="/css/bootstrap.min.css"
      as="style"
      onload="this.onload=null;this.rel='stylesheet'">

<noscript>
    <link rel="stylesheet" href="/css/bootstrap.min.css">
</noscript>
<!--<link href="css/bootstrap.min.css" rel="stylesheet">-->
<link href="css/style.css" rel="stylesheet">
<link rel="preload" as="style" href="css/recruitment-service-countries.css" fetchpriority="low" onload="this.onload=null;this.rel='stylesheet'">
<noscript><link rel="stylesheet" href="css/recruitment-service-countries.css"></noscript>
<!--<link rel="stylesheet" href="css/homepage-optimization.css">-->
<link rel="preload"
      href="/css/homepage-optimization.css"
      as="style"
      onload="this.onload=null;this.rel='stylesheet'">

<noscript>
    <link rel="stylesheet" href="/css/homepage-optimization.css">
</noscript>
<link rel="preload"
      href="/css/contact-offices.css"
      as="style"
      fetchpriority="low"
      onload="this.onload=null;this.rel='stylesheet'">

<noscript>
    <link rel="stylesheet" href="/css/office.css">
</noscript>

<style>
.supply-grid .card picture{display:block;width:100%;line-height:0;}
.supply-grid .card picture img{display:block;width:100%;height:auto;aspect-ratio:768/399;object-fit:cover;}
.wa-header picture{display:block;flex:0 0 auto;line-height:0;}
.wa-header picture img{display:block;width:200px;height:200px;max-width:100%;object-fit:cover;}
@media (max-width:767px){
  .supply-grid .card picture img{aspect-ratio:320/166;}
  .wa-header picture img{width:100px;height:100px;}
}

/* Performance-safe compositor hints, no layout changes. */
.ayk-se-track,.ticker-track{transform:translate3d(0,0,0);backface-visibility:hidden;}
@media (prefers-reduced-motion:reduce){.ayk-se-track,.ticker-track{animation:none!important;}}
</style>

<noscript>

</noscript>


<script>
/* Lightweight delegated AJAX handler for all manpower forms. */
document.addEventListener("submit", function (event) {
    const form = event.target.closest("form.manpower-form");
    if (!form) return;

    event.preventDefault();

    if (form.dataset.submitting === "1") return;
    form.dataset.submitting = "1";

    const formId = form.dataset.formId || "";
    const submitButton = form.querySelector("button[type=submit]");
    if (submitButton) submitButton.disabled = true;

    const formData = new FormData(form);

    fetch(window.location.href, {
        method: "POST",
        headers: {
            "X-Requested-With": "XMLHttpRequest"
        },
        body: formData,
        credentials: "same-origin"
    })
    .then(function (response) {
        if (!response.ok) throw new Error("Request failed");
        return response.text();
    })
    .then(function (html) {
        const template = document.createElement("template");
        template.innerHTML = html.trim();

        const newForm = template.content.querySelector(
            'form[data-form-id="' + CSS.escape(formId) + '"]'
        );

        if (newForm) {
            form.replaceWith(newForm);

            if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2) {
                window.jQuery(newForm).find(".select2").select2();
            }
        }
    })
    .catch(function () {
        form.dataset.submitting = "0";
        if (submitButton) submitButton.disabled = false;
    });
});
</script>

    </head>
    

    <body>
       
        <?php include("includes/navbar.php"); ?>






<main>
        
 <?php include __DIR__ . '/includes/hero-section.php'; ?>
    
    
    
    
    
    

<div class="ticker">
    <div class="ticker-track">
        <span>
             We provide skilled Pakistani manpower for global projects • 
             We also supply international workforce from global markets • 
             Fast deployment & verified candidates available
        </span>
    </div>
</div>








<!-- New Redesigned -->
 <!-- =====================================================================
     NEW SUPPLY SECTION  (prefix: mpx-)
     Replace the old <section class="supply"> ... </section> in index.php
     with everything below (the <style> block + the <section>).
     Every class starts with "mpx-" and every rule starts with ".mpx",
     so nothing else on the site can be affected, and the old .supply /
     .card / .why-list CSS is no longer used by this section.
     ===================================================================== -->
<style>
/* =========================================================
   EXACT ORIGINAL LOOK - FIXED RESPONSIVENESS
   ========================================================= */

/* Desktop Base Styles (Wahi jo aapke paas the) */
.mpx{--mpx-bg:url('img/skilled-unskilled.webp');--mpx-navy:#0a2350;--mpx-red:#e4202e;--mpx-text:#1b2433;--mpx-pink:#fde8eb;position:relative;padding:48px 40px 56px;background:var(--mpx-bg) center/cover no-repeat,#e3eefb;overflow:hidden;font-family:'Poppins',Arial,sans-serif;color:var(--mpx-text);box-sizing:border-box}
.mpx *,.mpx *::before,.mpx *::after{box-sizing:border-box}

.mpx .mpx-wrap{position:relative;z-index:1;max-width:80%;margin:0 auto;display:grid;grid-template-columns:1.8fr 1fr;gap:28px;align-items:start}

.mpx .mpx-bar{width:94px;height:5px;background:var(--mpx-red);border-radius:3px;margin:0 0 18px}
.mpx .mpx-title{margin:0;padding:0;font-size:clamp(30px,3.6vw,50px);line-height:1.05;font-weight:800;color:var(--mpx-navy);letter-spacing:-.5px}
.mpx .mpx-intro{margin:20px 0 28px;max-width:830px;font-size:17px;line-height:1.45;color:var(--mpx-text)}
.mpx .mpx-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.mpx .mpx-card{background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 8px 22px rgba(30,70,130,.12);display:flex;flex-direction:column}
.mpx .mpx-card picture{display:block;line-height:0}
.mpx .mpx-card img{display:block;width:100%;height:150px;object-fit:cover}
.mpx .mpx-card .mpx-lbl{display:flex;align-items:center;padding:14px 18px;min-height:76px;font-size:16px;line-height:1.25;font-weight:700;color:var(--mpx-navy)}
.mpx a.mpx-btn{display:inline-flex;align-items:center;gap:8px;margin-top:22px;padding:13px 32px;border:2px solid var(--mpx-red);border-radius:12px;background:#fff;color:var(--mpx-red);font-size:17px;font-weight:700;line-height:1.2;text-decoration:none;transition:all .3s ease}
.mpx a.mpx-btn:hover{background:var(--mpx-red);color:#fff}
.mpx .mpx-why{display:flex;flex-direction:column;background:rgba(255,255,255,.85);border-radius:26px;padding:13px;box-shadow:0 10px 30px rgba(30,70,130,.15);margin-top:20px}

/* Aapke Approved Changes (Icon Color & Red Bar) */
.mpx .mpx-why-head{display:flex;align-items:center;gap:18px;background:linear-gradient(135deg, #164585, #092554);border-radius:28px;padding:15px 20px}
.mpx .mpx-why-head svg{width:76px;height:76px;flex:none}
.mpx .mpx-why-title{
    position: relative;
    margin:0;
    padding:0 0 0 20px;
    color:#fff;
    font-size:clamp(20px,1.9vw,27px);
    line-height:1.2;
    font-weight:700
}
.mpx .mpx-why-title::before {
    content: "";
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    width: 4px;
    height: 75%;
    background-color: var(--mpx-red);
    border-radius: 2px;
}

.mpx .mpx-list{list-style:none;margin:0;padding:3px 10px 4px 8px;flex:1;display:flex;flex-direction:column;justify-content:space-between}
.mpx .mpx-list li{display:flex;align-items:center;gap:16px;flex:1;margin:0;padding:6px 0;border-bottom:1px solid #dde3ec}
.mpx .mpx-list li:last-child{border-bottom:0}
.mpx .mpx-ic{width:62px;height:50px;flex:none;border-radius:12px;background:var(--mpx-pink);display:flex;align-items:center;justify-content:center;color:var(--mpx-red)}
.mpx .mpx-ic svg{width:28px;height:28px;fill:none;stroke:currentColor;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.mpx .mpx-list span.mpx-tx{font-size:16.5px;line-height:1.3;font-weight:500;color:#111827}


/* =========================================================
   RESPONSIVE FIXES (Sirf Mobile/Tablet ke liye)
   ========================================================= */

/* Tablet */
@media(max-width: 1000px) {
    .mpx .mpx-wrap {
        max-width: 95%; /* 80% se barha kar 95% kiya taake squeeze na ho */
        grid-template-columns: 1fr; /* Left aur Right ko stack kiya */
    }
    .mpx .mpx-why {
        margin-top: 30px;
    }
}

/* Mobile */
@media(max-width: 620px) {
    .mpx {
        padding: 32px 18px; 
    }
    .mpx .mpx-wrap {
        max-width: 100%; /* Mobile par full width */
    }
    .mpx .mpx-cards {
        grid-template-columns: 1fr; /* 1 column kiya taake images stretch na hon */
        gap: 16px;
    }
    .mpx .mpx-card img {
        height: auto; /* Fixed height hatadi */
        aspect-ratio: 16 / 9; /* Natural ratio lagaya taake kharab na ho */
    }
    .mpx .mpx-card .mpx-lbl {
        font-size: 14px;
        padding: 14px 16px;
        min-height: auto;
    }
    
    /* Right Card Fixes */
    .mpx .mpx-why-head {
        gap: 12px;
        padding: 12px 15px;
    }
    .mpx .mpx-why-head svg {
        width: 55px; /* Icon thora chota kiya */
        height: 55px;
    }
    .mpx .mpx-why-title {
        font-size: 18px;
        padding-left: 12px;
    }
    .mpx .mpx-list span.mpx-tx {
        font-size: 14px;
    }
    .mpx .mpx-list li {
        padding: 10px 0;
    }
    .mpx .mpx-ic {
        width: 45px;
        height: 45px;
    }
    .mpx a.mpx-btn {
        width: 100%;
        justify-content: center;
    }
}




</style>

<section class="mpx" aria-labelledby="mpx-heading">
  <div class="mpx-wrap">

    <div class="mpx-left">
      <div class="mpx-bar"></div>
      <h2 class="mpx-title" id="mpx-heading">Skilled &amp; Unskilled Manpower Recruitment from Pakistan</h2>
      <p class="mpx-intro">AYK Global is a manpower supply and overseas recruitment agency in Pakistan, providing skilled, semi-skilled and unskilled Pakistani workers for construction, oil &amp; gas, healthcare, manufacturing, logistics, transport and domestic staffing projects across the GCC, Europe and global markets.</p>

      <div class="mpx-cards">

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Mobile_construction_workers.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_construction_workers.webp" alt="Skilled Construction Workers and Manpower Recruitment from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Construction &amp; Infrastructure Manpower</span>
        </div>

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Mobile_oil_gas_worker.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_oil_gas_worker.webp" alt="Oil &amp; Gas Manpower Recruitment and Skilled Workers from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Oil &amp; Gas &amp; Energy Manpower</span>
        </div>

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Mobile_halthcare_medical_staff.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_halthcare_medical_staff.webp" alt="Doctors, Nurses and Healthcare Manpower Recruitment from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Healthcare &amp; Medical Manpower</span>
        </div>

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Mobile_manufacturing_industrial.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_manufacturing_industrial.webp" alt="Manufacturing and Industrial Manpower Recruitment from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Manufacturing &amp; Industrial Manpower</span>
        </div>

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Mobile_drivers_transport_sectors.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_drivers_transport_sectors.webp" alt="Drivers and Transport Manpower Recruitment from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Drivers, Transport &amp; Mobility Manpower</span>
        </div>

        <div class="mpx-card">
          <picture>
            <source media="(max-width: 767px)" srcset="/img/mobile/Moblie_domestic_workers.webp" width="320" height="166">
            <img src="/img/desktop/Desktop_domestic_workers.webp" alt="Domestic and Caregiving Manpower Recruitment from Pakistan" loading="lazy" decoding="async" width="768" height="399">
          </picture>
          <span class="mpx-lbl">Domestic &amp; Caregiving Manpower</span>
        </div>

      </div>

      <a href="https://ayk.global/recruitment-by-industry.php" class="mpx-btn">View All Categories <span aria-hidden="true">&rarr;</span></a>
    </div>

    <aside class="mpx-why">
      <div class="mpx-why-head">
       <svg viewBox="0 0 64 64" aria-hidden="true">
  <!-- ribbon tails -->
  <path d="M22 44 L17 61 L27 56 L32 62 L34 46Z" fill="#fff"/>
  <path d="M42 44 L47 61 L37 56 L32 62 L30 46Z" fill="#fff"/>
  
  <!-- scalloped badge: 12 bumps -->
  <g fill="#fff" transform="translate(32 28)">
    <circle r="17"/>
    <g id="b">
      <circle cx="0" cy="-17" r="6"/>
    </g>
    <use href="#b" transform="rotate(30)"/>
    <use href="#b" transform="rotate(60)"/>
    <use href="#b" transform="rotate(90)"/>
    <use href="#b" transform="rotate(120)"/>
    <use href="#b" transform="rotate(150)"/>
    <use href="#b" transform="rotate(180)"/>
    <use href="#b" transform="rotate(210)"/>
    <use href="#b" transform="rotate(240)"/>
    <use href="#b" transform="rotate(270)"/>
    <use href="#b" transform="rotate(300)"/>
    <use href="#b" transform="rotate(330)"/>
  </g>
  
  <!-- Inner dark circle (taake background se match kare) -->
  <circle cx="32" cy="28" r="14.5" fill="#11366c"/>
  
  <!-- inner white ring -->
  <circle cx="32" cy="28" r="14.5" fill="none" stroke="#fff" stroke-width="1.5"/>
  
  <!-- White checkmark (Image 1 jaisa) -->
  <path d="M23 28.5l6.5 6.5 12-13" fill="none" stroke="#fff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
        <!-- <svg viewBox="0 0 64 64" aria-hidden="true"><g fill="#fff"><circle cx="32" cy="28" r="20"/><circle cx="53" cy="28" r="6.5"/><circle cx="49" cy="40.3" r="6.5"/><circle cx="38.5" cy="48" r="6.5"/><circle cx="25.5" cy="48" r="6.5"/><circle cx="15" cy="40.3" r="6.5"/><circle cx="11" cy="28" r="6.5"/><circle cx="15" cy="15.7" r="6.5"/><circle cx="25.5" cy="8" r="6.5"/><circle cx="38.5" cy="8" r="6.5"/><circle cx="49" cy="15.7" r="6.5"/><path d="M22 47L18 63l9-5 4 5 2-16zM42 47l4 16-9-5-4 5-2-16z"/></g><path d="M21 28.5l8 8 14-15" fill="none" stroke="#0a2350" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/></svg> -->
        <h2 class="mpx-why-title">Why Choose AYK as a Trusted HR Manpower Recruitment Agency in Pakistan?</h2>
      </div>

      <ul class="mpx-list">
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><circle cx="14" cy="11" r="7"/><path d="M10 17l-2 8 6-3 6 3-2-8M11 11l2 2 4-4"/></svg></span><span class="mpx-tx">Government Licensed &amp; Approved Recruitment Agency</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><circle cx="14" cy="9" r="4"/><circle cx="5" cy="11" r="3"/><circle cx="23" cy="11" r="3"/><path d="M6 24c0-6 4-8 8-8s8 2 8 8z"/></svg></span><span class="mpx-tx">Pre-Screened, Verified &amp; Trade-Tested Pakistani Workers</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><rect x="3" y="9" width="22" height="15" rx="2"/><path d="M10 9V6h8v3M3 16h22"/></svg></span><span class="mpx-tx">End-to-End Overseas Recruitment Services</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><circle cx="14" cy="8" r="4"/><circle cx="5" cy="11" r="3"/><circle cx="23" cy="11" r="3"/><path d="M6 25c0-7 4-9 8-9s8 2 8 9z"/></svg></span><span class="mpx-tx">Bulk Manpower Recruitment &amp; Project Hiring</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><circle cx="14" cy="14" r="11"/><ellipse cx="14" cy="14" rx="5" ry="11"/><path d="M3 14h22M5 8h18M5 20h18"/></svg></span><span class="mpx-tx">GCC, Europe &amp; International Recruitment Coverage</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><path d="M2 17l24-10-4 14-8-3-4 5v-6zM10 18l12-9"/></svg></span><span class="mpx-tx">Fast Workforce Deployment &amp; Mobilization</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><path d="M6 3h11l6 6v16H6zM17 3v6h6M10 14h8M10 18h5"/></svg></span><span class="mpx-tx">Complete Visa, Documentation &amp; Recruitment Compliance Support</span></li>
        <li><span class="mpx-ic"><svg viewBox="0 0 28 28" aria-hidden="true"><path d="M14 3l9 3v8c0 6-4 9-9 11-5-2-9-5-9-11V6z"/><path d="M9.5 14l3.5 3.5 6-7"/></svg></span><span class="mpx-tx">Replacement Guarantee for Reliable Manpower Solutions</span></li>
      </ul>
    </aside>

  </div>
</section>
        <!-- <section class="supply">

    <div class="supply-wrap">

        
        <div class="supply-left">
            
            <h2 style="font-size: 32px; font-weight: 600; ">Skilled & Unskilled Manpower Recruitment from Pakistan</h2>
            <p style="font-size: 16px !important; color: #000000 !important;">
    AYK Global is a manpower supply and overseas recruitment agency in Pakistan, providing skilled, semi-skilled and unskilled Pakistani workers for construction, oil & gas, healthcare, manufacturing, logistics, transport and domestic staffing
    projects across the GCC, Europe and global markets.</p>

        <div class="supply-grid">

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Mobile_construction_workers.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_construction_workers.webp"
                alt="Skilled Construction Workers and Manpower Recruitment from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Construction & Infrastructure Manpower</span>
    </div>

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Mobile_oil_gas_worker.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_oil_gas_worker.webp"
                alt="Oil & Gas Manpower Recruitment and Skilled Workers from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Oil & Gas & Energy Manpower</span>
    </div>

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Mobile_halthcare_medical_staff.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_halthcare_medical_staff.webp"
               alt="Doctors, Nurses and Healthcare Manpower Recruitment from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Healthcare & Medical Manpower</span>
    </div>

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Mobile_manufacturing_industrial.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_manufacturing_industrial.webp"
                alt="Manufacturing and Industrial Manpower Recruitment from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Manufacturing & Industrial Manpower</span>
    </div>

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Mobile_drivers_transport_sectors.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_drivers_transport_sectors.webp"
                alt="Drivers and Transport Manpower Recruitment from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Drivers, Transport & Mobility Manpower</span>
    </div>

    <div class="card">
        <picture>
            <source
                media="(max-width: 767px)"
                srcset="/img/mobile/Moblie_domestic_workers.webp"
                width="320"
                height="166"
            >
            <img
                src="/img/desktop/Desktop_domestic_workers.webp"
                alt="Domestic and Caregiving Manpower Recruitment from Pakistan"
                loading="lazy"
                decoding="async"
                width="768"
                height="399"
            >
        </picture>
        <span>Domestic & Caregiving Manpower</span>
    </div>

</div>

            <a href="https://ayk.global/recruitment-by-industry.php" class="view-all">View All Categories →</a>

        </div>

        
        <div class="supply-right">
          
            <div class="supply-right">

    <h2 style="font-size: 22px; font-weight: 600;">
        Why Choose AYK as a Trusted HR Manpower Recruitment Agency in Pakistan?
    </h2>

    <ul class="why-list">

        <li>
            <i class="fas fa-certificate"></i>
            <span>Government Licensed &amp; Approved Recruitment Agency</span>
        </li>

        <li>
            <i class="fas fa-user-check"></i>
            <span>Pre-Screened, Verified &amp; Trade-Tested Pakistani Workers</span>
        </li>

        <li>
            <i class="fas fa-briefcase"></i>
            <span>End-to-End Overseas Recruitment Services</span>
        </li>

        <li>
            <i class="fas fa-users"></i>
            <span>Bulk Manpower Recruitment &amp; Project Hiring</span>
        </li>

        <li>
            <i class="fas fa-globe"></i>
            <span>GCC, Europe &amp; International Recruitment Coverage</span>
        </li>

        <li>
            <i class="fas fa-plane-departure"></i>
            <span>Fast Workforce Deployment &amp; Mobilization</span>
        </li>

        <li>
            <i class="fas fa-file-contract"></i>
            <span>Complete Visa, Documentation &amp; Recruitment Compliance Support</span>
        </li>

        <li>
            <i class="fas fa-shield-alt"></i>
            <span>Replacement Guarantee for Reliable Manpower Solutions</span>
        </li>

    </ul>

</div>

</section> -->

<section class="vendor-sec">

    <div class="vendor-wrap">

        
        <div class="vendor-left">

            <h3 style="font-size: 32px; font-weight: 700;">Become an Approved Overseas Recruitment &amp; Manpower Vendor</h3>

            <p style="font-size: 16px !important; color: #000000 !important;"> We are a government-licensed manpower recruitment agency from Pakistan and an
    <strong><a href="https://ayk.global/recruitment-by-countries.php">international recruitment agency</a></strong>,
    ready to be onboarded as your approved <strong><a href="https://ayk.global/request-manpower-for-your-project.php">recruitment vendor for manpower supply</a></strong>,
    skilled Pakistani workforce and staffing requirements across the GCC, Europe and global markets.
</p>

           <ul class="vendor-points">

    <li style="font-size: 14px; color: #000000;">
        Government Licensed Overseas Recruitment Agency
    </li>

    <li style="font-size: 14px; color: #000000;">
        Approved Recruitment Vendor Registration &amp; Compliance
    </li>

    <li style="font-size: 14px; color: #000000;">
        Skilled, Semi-Skilled &amp; Unskilled Pakistani Workforce
    </li>

    <li style="font-size: 14px; color: #000000;">
        Fast Manpower Mobilization &amp; Visa Coordination
    </li>

    <li style="font-size: 14px; color: #000000;">
        GCC, Europe &amp; Global Recruitment Experience
    </li>

</ul>
         
            <p class="vendor-note">
We are ready to be registered as your approved manpower vendor. 
Kindly share your vendor registration process or requirements.
</p>

        </div>

        
        <div class="vendor-right">

            <p class="form-box-title">Request Vendor Registration</p>

<form class="manpower-form" data-form-id="vendor">

    <input
        type="hidden"
        name="form_type"
        value="vendor"
    >

    <!-- Honeypot -->
    <div
        style="
            position:absolute;
            left:-9999px;
            top:-9999px;
            width:1px;
            height:1px;
            overflow:hidden;
        "
        aria-hidden="true"
    >

        <label for="vendor-website">
            Website
        </label>

        <input
            type="text"
            id="vendor-website"
            name="website"
            tabindex="-1"
            autocomplete="off"
        >

    </div>


    <input
        type="text"
        name="company_name"
        placeholder="Company Name"
        maxlength="180"
        required
    >


    <input
        type="text"
        name="contact_person"
        placeholder="Contact Person"
        maxlength="120"
        required
    >


    <input
        type="email"
        name="email"
        placeholder="Email Address"
        maxlength="254"
        required
    >


    <input
        type="text"
        name="country"
        placeholder="Country"
        maxlength="100"
        required
    >


    <textarea
        name="message"
        placeholder="Tell us about your manpower requirements or vendor process"
        rows="3"
        maxlength="3000"
    ></textarea>


    <button type="submit">
        Register Us as Vendor
    </button>

</form>

        </div>

    </div>

</section>

 <section class="clients-sec">

    <div class="clients-container">

        
        <h3 style="font-size: 32px; font-weight: 600;"> Trusted Manpower Recruitment Services for International Employers</h3>
        <p style="font-size: 16px !important; color: #000000 !important;">
    We support international employers with reliable manpower recruitment and staffing
    solutions for their workforce needs. Whether you require skilled, semi-skilled or
    unskilled manpower for construction, manufacturing, logistics, facility management
    or other industries, we provide suitable Pakistani workers tailored to your
    requirements. Our focus on quality, reliable recruitment and timely workforce deployment makes us a trusted manpower agency for global employers.
</p>
        <div class="clients-slider"> 

            <div class="clients-track" style="animation-play-state:paused">
                
                
                                
                <img src="img/our clients/new_logos_2.webp" alt=" Stano print International " loading="lazy" decoding="async" fetchpriority="low">                
                <img src="img/our clients/client46.webp" alt="Hala" loading="lazy" decoding="async" fetchpriority="low">                
                <img src="img/our clients/client47.webp" alt="Lafemme" loading="lazy" decoding="async" fetchpriority="low">

                <img src="img/our clients/sj.webp" alt="SABK Aljusore commercial company" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/logo_new_12.webp" alt=" Adnan Radi General contracting Company " loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/logo_new_13.webp" alt="Pepsi Al jomaih bottling plant" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/logo_new_14.webp" alt="Apollo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logos_1.webp" alt="SABK Aljusore commercial company" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logos_3.webp" alt=" Adnan Radi General contracting Company " loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logos_5.webp" alt="Powrbot" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logos_6.webp" alt="Inseryal " loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logo_16.webp" alt="Qimmah Recruitment Establishment " loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logo_17.webp" alt=" Rawafed Najd Recruitment Company" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logo_18.webp" alt=" Bader Al-Monjaz for Recruitment Office" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/new_logo_19.webp" alt="Musaned Domestic Labor Program" loading="lazy" decoding="async" fetchpriority="low">
            
                <img src="img/our clients/logo_new_15.webp" alt="Salah Al Hamad Trad. Company" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/1.webp" alt="ASNAD AL SAWID Logistics Services logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/2.webp" alt="Wasi Steel Industries logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/3.webp" alt=" MARPCO logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/4.webp" alt="Barns logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/5.webp" alt="Nelofar Al-Shirq logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/6.webp" alt="ATLASBAY logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/7.webp" alt="Anmar Al-Riyada for Trading and General Contracting logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/8.webp" alt="ONMR logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/9.webp" alt="Royal Intl. Construction Company logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/10.webp" alt="Bisan Group logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/11.webp" alt="Mohammed Aqeel Foundation for Commerce, Trading, and Import logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/12.webp" alt="MANBA BEIURUT for Trading and Contracting logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/13.webp" alt="SEPCO logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/14.webp" alt="RYADAT Al Muwada for General Contracting logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/15.webp" alt="AGATE logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/16.webp" alt="DALLOW WATER logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/17.webp" alt="SAUDI EMAR for Real Estate Development logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/18.webp" alt="Tub National Contracting Company logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/19.webp" alt="Afaq Al-Madina Technical Services LLC logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/20.webp" alt="International Recruitment Company logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/21.webp" alt="Maharah Human Resources Company logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/22.webp" alt="Afras Avira for Teeth logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/23.webp" alt="Jabir M.Al-Jerais for Transportation Est." loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/24.webp" alt="MAKHAVI Machinery & Equipment Rental logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/25.webp" alt="Majeed Al-Harbi Ltd Co. logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/26.webp" alt="Saleh  Abdullah Al Hamad Co. logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/27.webp" alt="Marasy Al-Shamal General Contrating EST logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/28.webp" alt="Blackstone Energy logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/29.webp" alt="Industrial Support Services Company logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/30.webp" alt="Al-Manaratain Company and Ali Al-Shaab Group W.L.L logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/31.webp" alt="ESNAD Transport & Services W.L.L logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/32.webp" alt="Abo Al-Abd Chicken logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/33.webp" alt="SIGNATURE logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/34.webp" alt="EAMAR Al-Musanid logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/35.webp" alt="KAABI logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/36.webp" alt="Perfect Class Trading Company logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/37.webp" alt="The Deck Patong Holiday Rental logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/38.webp" alt="SANABIL Al-Jauf logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/39.webp" alt="NURSING PLACEMENT AGENCY logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/40.webp" alt="Sanabil Al-Jauf logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/41.webp" alt="IUC logo" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/our clients/42.webp" alt="Professional Mountains Co ltd logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/43.webp" alt="StanoPrint International LLC logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/44.webp" alt="IPS Group India logo" loading="lazy" decoding="async" fetchpriority="low">
                 <img src="img/our clients/client45.webp" alt="Sharp Corporation" loading="lazy" decoding="async" fetchpriority="low">
                 

                        </div>

        </div>

    </div>

</section>



<!-- ===================== AYK SUCCESS STORIES (scoped: .ss) ===================== -->
<style>
.ss{--gold:#FDBB30;--gold2:#FADB8D;--navy:#0a3a82;--ink:#0c2a5c;
  font-family:'Montserrat',Arial,sans-serif;color:#fff;text-align:left;
  position:relative;min-height:0;width:100%;margin:auto;box-sizing:border-box;
  padding:50px max(40px, calc((100% - 1520px) / 2)) 70px;
  background:url('img/bg-dark.png') center/cover no-repeat, #05447D;overflow:hidden}
.ss *{box-sizing:border-box;margin:0;padding:0;font-family:'Poppins',Arial,sans-serif}

.ss .ss-top{display:grid;grid-template-columns:1fr 1.62fr;gap:50px;align-items:center}

/* left */
.ss .ss-badge{display:inline-flex;align-items:center;gap:8px;border:1.5px solid var(--gold2);border-radius:30px;
  padding:9px 18px;font-size:13px;font-weight:700;letter-spacing:.5px;color:var(--gold2);background:rgba(10,40,100,.5)}
.ss .ss-h1{font-size:56px;line-height:1.05;font-weight:800;margin:22px 0 18px;color:#fff}
.ss .ss-h1 span{color:var(--gold2);display:block}
.ss .ss-lead{font-size:17px;line-height:1.5;max-width:540px;color:#fff}
.ss .ss-features{display:flex;margin:28px 0;max-width:560px}
.ss .ss-feat{flex:1;text-align:center;font-size:14px;font-weight:500;line-height:1.3;padding:0 8px;border-right:1px solid rgba(255,255,255,.3)}
.ss .ss-feat:last-child{border:0}
.ss .ss-actions{display:flex;align-items:center;gap:34px}
.ss .ss-btn{background:linear-gradient(180deg,#FBDD93,#FDBB30);color:#0c2a5c;font-weight:700;font-size:16px;border:0;
  border-radius:30px;padding:17px 32px;cursor:pointer;box-shadow:0 6px 16px rgba(0,0,0,.25)}
.ss .ss-watch{display:flex;align-items:center;gap:12px;background:none;border:0;color:#fff;font:700 16px 'Montserrat';cursor:pointer}

/* ===== button hover effect ===== */
.ss .ss-btn{position:relative;overflow:hidden;transition:transform .3s ease,box-shadow .3s ease,filter .3s ease}
.ss .ss-btn::after{content:"";position:absolute;top:0;left:-75%;width:50%;height:100%;
  background:linear-gradient(120deg,transparent,rgba(255,255,255,.6),transparent);
  transform:skewX(-20deg);transition:left .6s ease;pointer-events:none}
.ss .ss-btn:hover,.ss .ss-btn:focus-visible{transform:translateY(-4px) scale(1.03);filter:brightness(1.06);
  box-shadow:0 14px 28px rgba(253,187,48,.55),0 6px 16px rgba(0,0,0,.3)}
.ss .ss-btn:hover::after,.ss .ss-btn:focus-visible::after{left:130%}
.ss .ss-btn:active{transform:translateY(-1px) scale(1.01)}
.ss .ss-btn .ss-ic{transition:transform .3s ease}
.ss .ss-btn:hover .ss-ic,.ss .ss-btn:focus-visible .ss-ic{transform:translateX(6px)}

/* right slider */
.ss .ss-slider{position:relative}
.ss .ss-card{position:relative;height:430px;color:var(--ink);background:none}
.ss .ss-card::before{content:"";position:absolute;z-index:0;top:0;bottom:0;left:30%;right:0;
  border-radius:30px;background:url('img/bg-light.png') right bottom/cover no-repeat;
  box-shadow:0 18px 40px rgba(0,0,0,.35)}
.ss .ss-photo{position:absolute;z-index:2;left:30px;top:0;bottom:0;width:40%;
  border:5px solid var(--gold2);border-radius:30px;overflow:hidden;background:#111;
  transform:skewX(-8deg);box-shadow:0 10px 28px rgba(0,0,0,.35)}
.ss .ss-photo img{display:block;height:100%;width:calc(100% + 80px);max-width:none;margin-left:-40px;
  object-fit:cover;object-position:50% 8%;transform:skewX(8deg);transition:opacity .5s ease}

.ss .ss-info{position:absolute;z-index:1;inset:0;display:flex;flex-direction:column;justify-content:center;
  padding:24px 36px 24px calc(40% + 72px)}
.ss .ss-tag{align-self:flex-start;border:1px solid #05447D ;background: #cfecf7;border-radius:20px;
  padding:7px 18px;font-size:13px;font-weight:600;color:var(--ink)}
.ss .ss-h2{font-size:30px;line-height:1.2;font-weight:800;margin:14px 0 16px;color:#0c2a5c;white-space:nowrap}
.ss .ss-quote{position:relative;font-style:italic;font-size:16px;line-height:1.5;color: black;max-width:none;padding-left:46px}
.ss .ss-quote::before{content:"\201C";position:absolute;left:0;top:-8px;font-size:64px;line-height:1;font-family: 'Montserrat';
  color:#9fb3d3;font-style:normal;font-weight:800}
.ss .ss-stars{color:var(--gold);font-size:26px;letter-spacing:4px;margin:12px 0 10px}
.ss .ss-who{display:flex;align-items:center;gap:14px}
.ss .ss-who b{display:block;font-size:17px;color:#0c2a5c}
.ss .ss-who small{font-size:14px;color: black}

/* arrows + dots */
.ss .ss-arrow{position:absolute;z-index:3;top:50%;transform:translateY(-50%);width:50px;height:50px;
  border-radius:50%;background:#fff;color:#0c2a5c;border:0;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.3)}
.ss .ss-arrow.ss-l{left:5px}.ss .ss-arrow.ss-r{right:-26px}
.ss .ss-dots{display:flex;justify-content:center;gap:10px;margin-top:26px}
.ss .ss-dots span{width:15px;height:15px;border-radius:50%;background:#c1d7f8;cursor:pointer}
.ss .ss-dots span.ss-on{background:var(--gold)}

/* thumbs: auto-scrolling slider */
.ss .ss-thumbs{overflow:hidden;margin:28px 0 0;padding:8px 0}
.ss .ss-track{display:flex;align-items:center;width:max-content;animation:ss-scroll 40s linear infinite}
.ss .ss-thumbs:hover .ss-track{animation-play-state:paused}
.ss .ss-thumb{width:150px;height:126px;border-radius:10px;overflow:hidden;border:2px solid #fff;cursor:pointer;background:#222;flex:none;margin-right:16px}
.ss .ss-thumb.ss-on{border:3px solid var(--gold);box-shadow:0 0 14px rgba(247,185,40,.6)}
.ss .ss-thumb img{display:block;width:100%;height:100%;object-fit:cover;object-position:50% 0%}
@keyframes ss-scroll{from{transform:translate3d(0,0,0)}to{transform:translate3d(var(--ss-loop,-1400px),0,0)}}
@media (prefers-reduced-motion:reduce){.ss .ss-track{animation:none}}

/* svg icons */
.ss .ss-ic{width:1em;height:1em;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
.ss .ss-badge .ss-ic{width:18px;height:18px;color:var(--gold)}
.ss .ss-feat i{display:grid;place-items:center;width:56px;height:56px;margin:0 auto 10px;border-radius:50%;font-style:normal;
  background:radial-gradient(circle at 30% 25%, #3d84e6, #05447D);
  box-shadow:0 0 0 1px rgba(255,255,255,.12),0 4px 10px rgba(0,0,0,.25);color:#fff}
.ss .ss-feat i .ss-ic{width:26px;height:26px;stroke-width:1.8}
.ss .ss-btn{display:inline-flex;align-items:center;gap:10px}
.ss .ss-btn .ss-ic{width:20px;height:20px;stroke-width:2.5}
.ss .ss-watch b{display:grid;place-items:center;width:40px;height:40px;border:2px solid #fff;border-radius:50%}
.ss .ss-watch b .ss-ic{width:16px;height:16px;margin-left:2px}
.ss .ss-who i{display:grid;place-items:center;width:46px;height:46px;border-radius:50%;background: #dfe9fb; border: 1px solid #05447D; color: #0c3a82;font-style:normal}
.ss .ss-who i .ss-ic{width:22px;height:22px;fill:#0c3a82;stroke:#0c3a82}
.ss .ss-arrow{display:grid;place-items:center}
.ss .ss-arrow .ss-ic{width:27px;height:27px;stroke-width:3}



/* ================= RESPONSIVE ================= */

/* Large screens / laptops */
@media(max-width:1200px){
  .ss{padding:40px 40px 56px}
  .ss .ss-top{grid-template-columns:1fr;gap:40px}
  .ss .ss-h1{font-size:48px}
  .ss .ss-lead{max-width:100%}
  .ss .ss-features{max-width:100%}
  .ss .ss-arrow.ss-l{left:8px}
  .ss .ss-arrow.ss-r{right:-8px}
}

/* Tablet */
@media(max-width:900px){
  .ss{padding:36px 28px 48px}
  .ss .ss-h1{font-size:42px}
  .ss .ss-h2{white-space:normal;font-size:26px}
  .ss .ss-card{height:400px}
  .ss .ss-photo{left:20px;width:38%}
  .ss .ss-info{padding:24px 28px 24px calc(38% + 55px)}
  .ss .ss-quote{font-size:15px;padding-left:40px}
  .ss .ss-quote::before{font-size:52px}
  .ss .ss-features{margin:22px 0}
  .ss .ss-feat{font-size:13px}
  .ss .ss-feat i{width:50px;height:50px}
  .ss .ss-feat i .ss-ic{width:22px;height:22px}
  .ss .ss-thumb{width:130px;height:108px;margin-right:14px}
}

/* Mobile landscape / small tablet */
@media(max-width:700px){
  .ss{padding:28px 18px 40px}
  .ss .ss-h1{font-size:36px;margin:18px 0 14px}
  .ss .ss-lead{font-size:15px;line-height:1.55}
  .ss .ss-features{flex-wrap:wrap;gap:16px;margin:22px 0}
  .ss .ss-feat{flex:1 1 calc(50% - 8px);border:0;min-width:120px}
  .ss .ss-feat i{width:48px;height:48px}
  .ss .ss-card{height:auto}
  .ss .ss-card::before{left:0}
  .ss .ss-photo{position:relative;left:0;top:0;bottom:0;width:100%;height:320px;transform:none;
    border-radius:30px 30px 0 0;border-width:4px}
  .ss .ss-photo img{width:100%;margin:0;transform:none;object-position:50% 20%}
  .ss .ss-info{position:static;padding:24px 20px 28px}
  .ss .ss-h2{white-space:normal;font-size:24px}
  .ss .ss-quote{padding-left:0;padding-top:36px;font-size:15px}
  .ss .ss-quote::before{left:0;top:-4px;font-size:56px}
  .ss .ss-arrow{width:42px;height:42px}
  .ss .ss-arrow .ss-ic{width:22px;height:22px}
  .ss .ss-arrow.ss-l{left:-6px}
  .ss .ss-arrow.ss-r{right:-6px}
  .ss .ss-actions{flex-wrap:wrap;gap:16px}
  .ss .ss-btn{padding:15px 26px;font-size:15px}
  .ss .ss-watch{font-size:15px}
  .ss .ss-tag{font-size:12px;padding:6px 14px}
  .ss .ss-thumb{width:110px;height:92px;margin-right:12px;border-radius:8px}
  .ss .ss-dots span{width:12px;height:12px}
}

/* Mobile portrait */
@media(max-width:480px){
  .ss{padding:24px 14px 36px}
  .ss .ss-badge{font-size:11px;padding:7px 14px;gap:6px}
  .ss .ss-badge .ss-ic{width:15px;height:15px}
  .ss .ss-h1{font-size:30px;margin:16px 0 12px;line-height:1.1}
  .ss .ss-lead{font-size:14px}
  .ss .ss-features{gap:12px;margin:18px 0}
  .ss .ss-feat{flex:1 1 calc(50% - 6px);font-size:12px;min-width:100px;padding:0 4px}
  .ss .ss-feat i{width:44px;height:44px;margin-bottom:8px}
  .ss .ss-feat i .ss-ic{width:20px;height:20px}
  .ss .ss-actions{gap:12px}
  .ss .ss-btn{padding:14px 22px;font-size:14px;width:100%;justify-content:center}
  .ss .ss-watch{font-size:14px;width:100%;justify-content:center}
  .ss .ss-photo{height:260px;border-radius:24px 24px 0 0}
  .ss .ss-card::before{border-radius:24px}
  .ss .ss-info{padding:20px 16px 24px}
  .ss .ss-tag{font-size:11px;padding:5px 12px}
  .ss .ss-h2{font-size:20px;margin:12px 0}
  .ss .ss-quote{font-size:14px;line-height:1.55;padding-top:32px}
  .ss .ss-quote::before{font-size:46px;top:-2px}
  .ss .ss-stars{font-size:22px;letter-spacing:3px;margin:10px 0 8px}
  .ss .ss-who{gap:10px}
  .ss .ss-who i{width:40px;height:40px}
  .ss .ss-who i .ss-ic{width:20px;height:20px}
  .ss .ss-who b{font-size:15px}
  .ss .ss-who small{font-size:12px}
  .ss .ss-arrow{width:38px;height:38px}
  .ss .ss-arrow.ss-l{left:-4px}
  .ss .ss-arrow.ss-r{right:-4px}
  .ss .ss-arrow .ss-ic{width:20px;height:20px}
  .ss .ss-thumb{width:90px;height:76px;margin-right:10px;border-radius:8px}
  .ss .ss-thumbs{padding:6px 0;margin-top:22px}
  .ss .ss-dots{gap:8px;margin-top:20px}
  .ss .ss-dots span{width:10px;height:10px}
}

/* Very small phones */
@media(max-width:360px){
  .ss .ss-h1{font-size:26px}
  .ss .ss-feat{flex:1 1 100%}
  .ss .ss-thumb{width:80px;height:68px;margin-right:8px}
  .ss .ss-btn{font-size:13px;padding:13px 18px}
}

/* responsive */
/* @media(max-width:1200px){.ss{padding:40px 40px}.ss .ss-top{grid-template-columns:1fr}}
@media(max-width:700px){
.ss{padding:28px 18px}
.ss .ss-h1{font-size:38px}
.ss .ss-features{flex-wrap:wrap;gap:16px}
.ss .ss-feat{flex:1 1 40%;border:0}
.ss .ss-card{height:auto}
.ss .ss-card::before{left:0}
.ss .ss-photo{position:relative;left:0;top:0;bottom:0;width:100%;height:300px;transform:none;border-radius:30px 30px 0 0}
.ss .ss-photo img{width:100%;margin:0;transform:none}
.ss .ss-info{position:static;padding:24px 22px 26px}
.ss .ss-quote{padding-left:0;padding-top:40px;max-width:none}
.ss .ss-quote::before{left:0;top:-6px}
.ss .ss-arrow.ss-l{left:-8px}.ss .ss-arrow.ss-r{right:-8px}
.ss .ss-actions{flex-wrap:wrap;gap:18px}
} */
</style>

<section class="ss" aria-label="AYK Overseas Success Stories">
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <symbol id="ss-i-users" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></symbol>
    <symbol id="ss-i-file" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="m9 15 2 2 4-4"/></symbol>
    <symbol id="ss-i-plane" viewBox="0 0 24 24"><path d="M17.8 19.2 16 11l3.5-3.5C21 6 21.5 4 21 3c-1-.5-3 0-4.5 1.5L13 8 4.8 6.2c-.5-.1-.9.1-1.1.5l-.3.5c-.2.5-.1 1 .3 1.3L9 12l-2 3H4l-1 1 3 2 2 3 1-1v-3l3-2 3.5 5.3c.3.4.8.5 1.3.3l.5-.2c.4-.3.6-.7.5-1.2z"/></symbol>
    <symbol id="ss-i-hand" viewBox="0 0 24 24"><path d="m11 17 2 2a1 1 0 1 0 3-3"/><path d="m14 14 2.5 2.5a1 1 0 1 0 3-3l-3.88-3.88a3 3 0 0 0-4.24 0l-.88.88a1 1 0 1 1-3-3l2.81-2.81a5.79 5.79 0 0 1 7.06-.87l.47.28a2 2 0 0 0 1.42.25L21 4"/><path d="m21 3 1 11h-2"/><path d="M3 3 2 14l6.5 6.5a1 1 0 1 0 3-3"/><path d="M3 4h8"/></symbol>
    <symbol id="ss-i-trophy" viewBox="0 0 24 24"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"/></symbol>
    <symbol id="ss-i-user" viewBox="0 0 24 24"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></symbol>
    <symbol id="ss-i-left" viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></symbol>
    <symbol id="ss-i-right" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></symbol>
    <symbol id="ss-i-arrow" viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></symbol>
    <symbol id="ss-i-play" viewBox="0 0 24 24"><path d="M8 5v14l11-7z" fill="currentColor"/></symbol>
  </defs>
</svg>

  <div class="ss-top">
    <div>
      <div class="ss-badge"><svg class="ss-ic"><use href="#ss-i-trophy"/></svg> REAL PEOPLE, REAL OPPORTUNITIES</div>
      <h2 class="ss-h1">AYK Overseas <span>Success Stories</span></h2>
      <p class="ss-lead">Discover real journeys of candidates who turned their overseas career goals into reality with AYK’s end-to-end recruitment, visa and deployment support.</p>
      <div class="ss-features">
        <div class="ss-feat"><i><svg class="ss-ic"><use href="#ss-i-users"/></svg></i>Candidate<br>Screening</div>
        <div class="ss-feat"><i><svg class="ss-ic"><use href="#ss-i-file"/></svg></i>Visa &amp;<br>Documentation</div>
        <div class="ss-feat"><i><svg class="ss-ic"><use href="#ss-i-plane"/></svg></i>Deployment<br>Support</div>
        <div class="ss-feat"><i><svg class="ss-ic"><use href="#ss-i-hand"/></svg></i>Successful<br>Placement</div>
      </div>
      <div class="ss-actions">
        <button class="ss-btn" type="button" onclick="location.href='successful-clients.php'">Explore All Success Stories <svg class="ss-ic"><use href="#ss-i-arrow"/></svg></button>
        <button class="ss-watch" type="button"><b><svg class="ss-ic"><use href="#ss-i-play"/></svg></b> Watch Stories</button>
      </div>
    </div>

    <div class="ss-slider">
      <div class="ss-card">
        <div class="ss-photo"><img id="ssMainPhoto" src="img/1.jpeg" alt="Candidate"></div>
        <div class="ss-info">
          <span class="ss-tag">CANDIDATE SUCCESS</span>
          <h3 class="ss-h2">From Application to<br>Overseas Employment</h3>
          <p class="ss-quote">“AYK supported me at every step — from registration and documentation to visa processing and final deployment. The process was smooth, transparent and completely professional.”</p>
          <div class="ss-stars">★★★★★</div>
          <div class="ss-who"><i><svg class="ss-ic"><use href="#ss-i-user"/></svg></i><div><b>AYK Success Story</b><small>Overseas Employment Journey</small></div></div>
        </div>
      </div>
      <button class="ss-arrow ss-l" id="ssPrev" type="button" aria-label="Previous"><svg class="ss-ic"><use href="#ss-i-left"/></svg></button>
      <button class="ss-arrow ss-r" id="ssNext" type="button" aria-label="Next"><svg class="ss-ic"><use href="#ss-i-right"/></svg></button>
      <div class="ss-dots" id="ssDots"><span class="ss-on"></span><span></span><span></span><span></span></div>
    </div>
  </div>

  <div class="ss-thumbs">
    <div class="ss-track" id="ssTrack">
      <div class="ss-thumb ss-on"><img src="img/1.jpeg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/2.jpeg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/3.jpeg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/4.jpeg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/success/5.jpg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/success/6.jpg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/success/7.jpg" alt="" loading="lazy"></div>
      <div class="ss-thumb"><img src="img/success/8.jpg" alt="" loading="lazy"></div>
    </div>
  </div>
</section>

<script>
(function(){
  var root=document.querySelector('.ss'); if(!root) return;
  var track=document.getElementById('ssTrack');
  var originals=[].slice.call(track.querySelectorAll('.ss-thumb'));
  var N=originals.length;
  var dots=[].slice.call(root.querySelectorAll('#ssDots span'));
  var main=document.getElementById('ssMainPhoto');
  var cur=0, timer=null, DELAY=4500, SPEED=40, sets=1, setW=0;
  var reduce=window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  originals.forEach(function(t,i){ t.setAttribute('data-i',i); });
  var srcs=originals.map(function(t){ return t.querySelector('img').getAttribute('src'); });

  /* ---------- thumbs marquee ---------- */
  function build(){
    setW=0;
    originals.forEach(function(t){
      setW+=t.getBoundingClientRect().width+(parseFloat(getComputedStyle(t).marginRight)||0);
    });
    if(!setW) return;
    var need=Math.ceil(root.clientWidth/setW)+1;
    while(sets<need){
      originals.forEach(function(t){
        var c=t.cloneNode(true);
        c.setAttribute('aria-hidden','true');
        track.appendChild(c);
      });
      sets++;
    }
    track.style.setProperty('--ss-loop','-'+setW+'px');
    track.style.animationDuration=(setW/SPEED)+'s';
  }

  /* ---------- main photo ---------- */
  function show(i){
    cur=(i+N)%N;
    [].forEach.call(track.querySelectorAll('.ss-thumb'),function(t){
      t.classList.toggle('ss-on', +t.getAttribute('data-i')===cur);
    });
    dots.forEach(function(d,k){ d.classList.toggle('ss-on',k===cur%dots.length); });
    main.style.opacity=0;
    setTimeout(function(){
      main.onload=main.onerror=function(){ main.style.opacity=1; };
      main.src=srcs[cur];
    },250);
  }

  /* ---------- autoplay (4.5s) ---------- */
  function start(){
    if(reduce) return;
    clearInterval(timer);
    timer=setInterval(function(){ show(cur+1); },DELAY);
  }

  track.addEventListener('click',function(e){
    var t=e.target.closest('.ss-thumb'); if(!t) return;
    show(+t.getAttribute('data-i')); start();
  });
  dots.forEach(function(d,i){ d.onclick=function(){ show(i); start(); }; });
  document.getElementById('ssPrev').onclick=function(){ show(cur-1); start(); };
  document.getElementById('ssNext').onclick=function(){ show(cur+1); start(); };

  build();
  window.addEventListener('load',build);
  window.addEventListener('resize',build,{passive:true});
  start();
})();
</script>
<!-- ===================== /AYK SUCCESS STORIES ===================== -->
<!-- ===================== /AYK SUCCESS STORIES ===================== -->
<!-- <section class="ayk-se" aria-labelledby="ayk-se-title">
<div class="ayk-se-wrap">

  <div class="ayk-se-head">
    <h3 id="ayk-se-title" style="font-size:32px; font-weight:600;">Successful Overseas Employment Stories</h3>
    <p style="font-size: 16px !important; color: #000000 !important;">Explore real candidate success stories and learn how AYK supports overseas recruitment, documentation and deployment.</p>
  </div>

  <div class="ayk-se-feature">
    <div class="ayk-se-copy">
      <span class="ayk-se-pill"><i class="fas fa-circle-check" aria-hidden="true"></i> Candidate Success</span>
      <h3 style="font-size: 32px; font-weight: 600;">Overseas Recruitment, Visa Processing &amp; Manpower Deployment</h3>
      <p style="font-size: 16px !important; color: #000000 !important;">From registration and screening to selection, documentation, <strong><a href="https://ayk.global/visa-processing.php">Visa Processing</a></strong> and deployment, we support the full recruitment journey and celebrate every successful placement.</p>
      <p style="font-size: 16px !important; color: #000000 !important;">Our overseas recruitment services cover candidate screening, documentation, visa processing and reliable manpower deployment for international employers.</p>
      <div class="ayk-se-points">
        <span style="font-weight: 600;">
    <i class="fas fa-user-check" aria-hidden="true"></i> Screening &amp; selection
</span>

<span style="font-weight: 600;">
    <i class="fas fa-file-circle-check" aria-hidden="true"></i> Documentation support
</span>

<span style="font-weight: 600;">
    <i class="fas fa-passport" aria-hidden="true"></i> Visa processing
</span>

<span style="font-weight: 600;">
    <i class="fas fa-plane-departure" aria-hidden="true"></i> Overseas deployment
</span>
      </div>
      
      <a href="successful-clients.php" class="ayk-se-btn">Explore All Success Stories <i class="fas fa-arrow-right" aria-hidden="true"></i></a>
    </div>

    <div class="ayk-se-feature-photo">
      <img src="/img/clients/successful_clients(1).jpeg" alt="Successful overseas employment candidate" loading="lazy" decoding="async" class="ayk-se-active" width="900" height="1100" fetchpriority="low">
      <img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(14).jpeg" alt="Successful overseas employment candidate" loading="lazy" decoding="async" width="900" height="1100" fetchpriority="low">
      <img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(12).jpeg" alt="Successful overseas employment candidate" loading="lazy" decoding="async" width="900" height="1100" fetchpriority="low">
      <img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(19).jpeg" alt="Successful overseas employment candidate" loading="lazy" decoding="async" width="900" height="1100" fetchpriority="low">
      <div class="ayk-se-badge"><i class="fas fa-award" aria-hidden="true"></i><span><strong>AYK Success Story</strong><small>Overseas employment journey</small></span></div>
    </div>
  </div>

  <div class="ayk-se-gallery" aria-label="Successful overseas employment photographs">
    <div class="ayk-se-track" id="aykSeTrack">
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(1).jpeg" alt="Success story 1" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(10).jpeg" alt="Success story 10" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(11).jpeg" alt="Success story 11" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(12).jpeg" alt="Success story 12" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(13).jpeg" alt="Success story 13" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(14).jpeg" alt="Success story 14" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(15).jpeg" alt="Success story 15" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(16).jpeg" alt="Success story 16" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(17).jpeg" alt="Success story 17" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(18).jpeg" alt="Success story 18" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(19).jpeg" alt="Success story 19" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(20).jpeg" alt="Success story 20" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(21).jpeg" alt="Success story 21" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(23).jpeg" alt="Success story 23" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(24).jpeg" alt="Success story 24" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(25).jpeg" alt="Success story 25" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
      <article class="ayk-se-card"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" data-src="/img/clients/successful_clients(26).jpeg" alt="Success story 26" loading="lazy" decoding="async" width="600" height="760" fetchpriority="low"></article>
    </div>
  </div>

  <div class="ayk-se-bottom">
    <div>
    <strong style="font-size: 20px; font-weight: 600;">
        Your Overseas Career Could Be the Next AYK Success Story
    </strong>

    <span style="font-size: 14px; color: #000000;">
        Explore real candidate journeys and learn how AYK supports overseas employment end to end.
    </span>
</div>

<a href="successful-clients.php" class="ayk-se-btn ayk-se-outline">
    View All Success Stories
    <i class="fas fa-arrow-right" aria-hidden="true"></i></a>

</div>
</section> -->



<!-- <style>
.ayk-se{position:relative;overflow:hidden;background:#fff;padding:64px 20px 68px;border-top:1px solid #e6eef5;border-bottom:1px solid #e6eef5;color:#18344d}
.ayk-se:before{content:"";position:absolute;width:460px;height:460px;right:-230px;top:-240px;border-radius:50%;background:rgba(12,104,168,.05);pointer-events:none}
.ayk-se-wrap{position:relative;z-index:1;max-width:1200px;margin:0 auto}

.ayk-se-head{text-align:center;max-width:780px;margin:0 auto 30px}
.ayk-se-eyebrow{display:inline-flex;align-items:center;gap:8px;color:#0b6ca9;font-size:11px;font-weight:800;letter-spacing:1.3px;text-transform:uppercase;margin-bottom:10px}
.ayk-se-head h2{margin:0 0 10px;color:#0b4774;font-size:clamp(27px,3vw,38px);line-height:1.15;font-weight:800;letter-spacing:-.5px}
.ayk-se-head p{margin:0 auto;color:#68798b;font-size:14px;line-height:1.75;max-width:680px}

.ayk-se-feature{display:grid;grid-template-columns:1fr .78fr;gap:0;border:1px solid #dfe9f2;border-radius:20px;background:#fff;box-shadow:0 14px 40px rgba(17,64,101,.08);margin-bottom:22px;overflow:hidden}
.ayk-se-copy{padding:34px 36px}
.ayk-se-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #d5eaf8;background:#edf8ff;color:#0b6ca9;border-radius:999px;padding:7px 12px;font-size:10px;font-weight:800;letter-spacing:.7px;text-transform:uppercase}
.ayk-se-copy h3{margin:14px 0 10px;color:#103e62;font-size:clamp(21px,2.2vw,28px);line-height:1.22;font-weight:800}
.ayk-se-copy>p{margin:0 0 18px;color:#66788b;font-size:13.5px;line-height:1.8;max-width:520px}
.ayk-se-points{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-bottom:20px}
.ayk-se-points span{display:flex;align-items:center;gap:7px;color:#304b62;font-size:11px;font-weight:700}
.ayk-se-points i{color:#0b70b2}

.ayk-se-stats-row{display:flex;gap:0;margin-bottom:22px;border-top:1px solid #e7edf3;border-bottom:1px solid #e7edf3;padding:14px 0}
.ayk-se-stats-row div{flex:1;text-align:left;padding-right:10px}
.ayk-se-stats-row strong{display:block;color:#0b67a2;font-size:20px;line-height:1.1;font-weight:800}
.ayk-se-stats-row span{display:block;margin-top:3px;color:#8095a8;font-size:9.5px;font-weight:700;letter-spacing:.4px;text-transform:uppercase}

.ayk-se-btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:12px 18px;background:#0b67a2;color:#fff!important;text-decoration:none;border-radius:10px;font-size:12px;font-weight:800;box-shadow:0 8px 20px rgba(11,103,162,.18);transition:.2s ease}
.ayk-se-btn:hover{background:#084f7e;transform:translateY(-2px)}

.ayk-se-feature-photo{position:relative;overflow:hidden;min-height:430px}
.ayk-se-feature-photo img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;object-position:center top;opacity:0;transition:opacity 1.4s ease}
.ayk-se-feature-photo img.ayk-se-active{opacity:1}
.ayk-se-feature-photo:after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 45%,rgba(5,34,56,.78) 100%);pointer-events:none;z-index:1}
.ayk-se-badge{position:absolute;z-index:2;left:18px;right:18px;bottom:17px;display:flex;align-items:center;gap:10px;color:#fff}
.ayk-se-badge i{display:grid;place-items:center;width:36px;height:36px;flex:0 0 36px;border-radius:50%;background:#0b67a2}
.ayk-se-badge strong,.ayk-se-badge small{display:block}.ayk-se-badge strong{font-size:12.5px}.ayk-se-badge small{margin-top:2px;font-size:10px;opacity:.9}

.ayk-se-gallery{position:relative;overflow:hidden;margin:0 -20px 22px;padding:2px 0}
.ayk-se-gallery:before,.ayk-se-gallery:after{content:"";position:absolute;top:0;bottom:0;width:60px;z-index:2;pointer-events:none}
.ayk-se-gallery:before{left:0;background:linear-gradient(90deg,#fff,transparent)}
.ayk-se-gallery:after{right:0;background:linear-gradient(-90deg,#fff,transparent)}
.ayk-se-track{display:flex;gap:13px;padding:0 20px;width:max-content}
.ayk-se-track.ayk-se-anim{animation:ayk-se-scroll linear infinite}
.ayk-se-gallery:hover .ayk-se-track{animation-play-state:paused}
.ayk-se-card{flex:0 0 150px;height:188px;overflow:hidden;border:1px solid #dfe8ef;border-radius:13px;background:#fff;box-shadow:0 6px 16px rgba(17,64,101,.07)}
.ayk-se-card img{display:block;width:100%;height:100%;object-fit:cover;object-position:center top;transition:transform .4s ease}
.ayk-se-card:hover img{transform:scale(1.05)}

.ayk-se-bottom{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:18px 22px;border:1px solid #dfe8f0;border-radius:16px;background:#f7fbff}
.ayk-se-bottom strong{display:block;color:#103e62;font-size:13.5px}.ayk-se-bottom span{display:block;margin-top:4px;color:#718196;font-size:11px;line-height:1.55}
.ayk-se-outline{background:#fff;color:#0b67a2!important;border:1px solid #bcd8eb;box-shadow:none;white-space:nowrap}.ayk-se-outline:hover{background:#eef8ff;color:#084f7e!important}

@keyframes ayk-se-scroll{from{transform:translate3d(0,0,0)}to{transform:translate3d(var(--ayk-se-loop,-2000px),0,0)}}

@media (max-width:900px){
  .ayk-se-feature{grid-template-columns:1fr}
  .ayk-se-copy{padding:26px}
  .ayk-se-feature-photo{min-height:280px;order:-1}
}
@media (max-width:650px){
  .ayk-se{padding:48px 14px 54px}
  .ayk-se-head h2{font-size:25px}
  .ayk-se-points{grid-template-columns:1fr}
  .ayk-se-stats-row{flex-wrap:wrap;row-gap:12px}
  .ayk-se-stats-row div{flex:0 0 50%}
  .ayk-se-card{flex-basis:130px;height:164px}
  .ayk-se-bottom{align-items:flex-start;flex-direction:column}
  .ayk-se-outline{width:100%}
}
@media (prefers-reduced-motion:reduce){.ayk-se-track{animation:none}.ayk-se-feature-photo img{transition:none}}
</style> -->


<style>
/* ===== AYK ABOUT SECTION (scoped) ===== */
.ayk-ab{
  --ab-navy:#0f1f4d; --ab-red:#d6173a; --ab-text:#18213a; --ab-line:#e3e8f1;
  --ab-bg:url("img/government-certified.webp");
  padding:80px 20px;
  
  /* Yahan humne gradient add kiya hai jo neeche se fade hoga */
background: linear-gradient(to bottom, rgba(1, 11, 51, 0) 90%, #010b33 100%), var(--ab-bg) center top / cover no-repeat, #010b33;
  /* background: linear-gradient(to bottom, rgba(247, 249, 252, 0) 60%, rgba(247, 249, 252, 1) 100%), var(--ab-bg) center/cover no-repeat, #f7f9fc;  */
  
  font-family:"Inter","Poppins",system-ui,sans-serif;
  color:var(--ab-text);
  position: relative; 
}
/* .ayk-ab{
  --ab-navy:#0f1f4d; --ab-red:#d6173a; --ab-text:#18213a; --ab-line:#e3e8f1;
  --ab-bg:url("img/government-certified.webp");
  padding:80px 20px;
  
  background:var(--ab-bg) center/cover no-repeat,#f7f9fc;

  font-family:"Inter","Poppins",system-ui,sans-serif;
  color:var(--ab-text);
} */

.ayk-ab *,.ayk-ab *::before,.ayk-ab *::after{box-sizing:border-box}
 
.ayk-ab .ayk-ab-box{
  max-width:1280px;margin:0 auto;padding:0;
  display:grid;grid-template-columns:1.08fr .92fr;
    column-gap:clamp(30px,5vw,80px);row-gap:22px;align-items:start;
  /* column-gap:clamp(20px,3vw,40px);row-gap:22px;align-items:start; */
}

.ayk-ab .ayk-ab-head{grid-column:1/-1}
.ayk-ab .ayk-ab-left{grid-column:1}

.ayk-ab .ayk-ab-card{grid-column:2;align-self:stretch;display:flex;flex-direction:column}
.ayk-ab .ayk-ab-left,.ayk-ab .ayk-ab-card{min-width:0}
/* .ayk-ab .ayk-ab-card{grid-column:2;align-self:end} */
 
/* heading */

/* .ayk-ab .ayk-ab-eyebrow{
  display:flex;align-items:center;gap:14px;margin:0;
  font-size:14px;font-weight:700;color:var(--ab-navy);letter-spacing:.3px;text-transform:uppercase;line-height:1.2;
}
.ayk-ab .ayk-ab-eyebrow::before{content:"";width:48px;height:4px;background:var(--ab-red);border-radius:2px} */

.ayk-ab .ayk-ab-title{
  margin:20px 0 22px;padding:0;
  font-size:clamp(28px,3.7vw,42px);line-height:1.15;font-weight:700;color:var(--ab-navy);letter-spacing:-.5px;
}
.ayk-ab .ayk-ab-title .ayk-ab-no{color:var(--ab-red)}
.ayk-ab .ayk-ab-br{display:inline}

.ayk-ab .ayk-ab-rule{width:56px;height:4px;background:var(--ab-red);border-radius:2px}
 
/* paragraphs */
.ayk-ab .ayk-ab-left p{margin:0 0 16px;font-size:15.5px;line-height:1.55;color:var(--ab-text)}
.ayk-ab .ayk-ab-left a{color:var(--ab-navy);font-weight:700;text-decoration:none}
/* .ayk-ab .ayk-ab-left a:hover{text-decoration:underline} */
.ayk-ab .ayk-ab-left strong{font-weight:700;color:var(--ab-navy)}
 
/* buttons */
.ayk-ab .ayk-ab-btns{display:flex;gap:18px;margin-top:26px;flex-wrap:wrap}
.ayk-ab .ayk-ab-btn{
  display:inline-flex;align-items:center;justify-content:center;gap:10px;
  height:48px;padding:0 20px;border-radius:10px;
  font-size:14px;font-weight:600;text-transform:uppercase;text-decoration:none;line-height:1;
  transition:transform .15s ease,box-shadow .15s ease;
}


.ayk-ab .ayk-ab-btn svg{width:20px;height:20px;flex:none}
.ayk-ab .ayk-ab-btn:focus-visible{outline:3px solid var(--ab-navy);outline-offset:2px}
.ayk-ab .ayk-ab-btn:hover{transform:translateY(-1px);text-decoration:none}
.ayk-ab a.ayk-ab-btn-outline{background:#fff;color:var(--ab-navy);border:2px solid var(--ab-navy);min-width:200px}
.ayk-ab a.ayk-ab-btn-fill{background:linear-gradient(#E02454,#E02454);color:#fff;border:0;min-width:220px;box-shadow:0 6px 16px rgba(214,23,58,.3)}


/* Button Hovers */
.ayk-ab a.ayk-ab-btn-outline:hover{
    background: var(--ab-navy);
    color: #fff;
    border:2px solid #ffff;
}

.ayk-ab a.ayk-ab-btn-fill:hover{
    background: #fff;
    color: #E02454;
    border: 2px solid #E02454;
}

 
/* certificate card */
.ayk-ab .ayk-ab-card{background:rgba(255,255,255,.92);border-radius:22px;box-shadow:0 8px 30px rgba(30,60,120,.15);overflow:hidden}
/* .ayk-ab .ayk-ab-card-head{display:flex;align-items:center;gap:18px;padding:22px 26px;background:linear-gradient(#e9f2fd,#f4f8fe)} */
.ayk-ab .ayk-ab-card-head{display:flex;align-items:center;gap:18px;padding:22px 26px;background:linear-gradient(rgba(214,230,250,.6),rgba(232,241,252,.35))}

.ayk-ab .ayk-ab-card-head svg{width:44px;height:44px;flex:none}
.ayk-ab .ayk-ab-card-head .ayk-ab-bar{width:2px;align-self:stretch;background:var(--ab-red)}
.ayk-ab .ayk-ab-card-title{margin:0;font-size:25px;line-height:1.15;font-weight:800;color:var(--ab-navy)}
 
.ayk-ab .ayk-ab-checks{list-style:none;margin:0;padding:6px 30px 0}
.ayk-ab .ayk-ab-checks li{
  display:flex;align-items:center;gap:14px;margin:0;padding:13px 0;
  font-size:15.5px;line-height:1.4;color:var(--ab-text);border-bottom:1px solid var(--ab-line);
}
.ayk-ab .ayk-ab-checks li:last-child{border-bottom:0}
.ayk-ab .ayk-ab-checks li::before{
  content:"";flex:none;width:24px;height:24px;border-radius:50%;
  background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 14 14' fill='none' stroke='%23fff' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M2.5 7.5l3 3 6-7'/%3E%3C/svg%3E") center/14px no-repeat,var(--ab-red);
}
 
.ayk-ab .ayk-ab-certified{
      display:flex;align-items:center;gap:16px;margin:auto 30px 16px;padding-top:18px;
  /* display:flex;align-items:center;gap:16px;margin:18px 30px 16px; */
  font-size:16px;font-weight:800;letter-spacing:1.5px;color:var(--ab-navy);text-transform:uppercase;
}
.ayk-ab .ayk-ab-certified::before,.ayk-ab .ayk-ab-certified::after{content:"";flex:1;height:1px;background:#cfd6e4}
 
.ayk-ab .ayk-ab-logos{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0 22px 26px}
.ayk-ab .ayk-ab-logo{
  height:104px;display:flex;align-items:center;justify-content:center;
  background:#fff;border-radius:14px;box-shadow:0 3px 12px rgba(30,60,120,.12);padding:10px;
}
.ayk-ab .ayk-ab-logo img{display:block;width:auto;height:auto;max-width:100%;max-height:84px;object-fit:contain}
 
/* responsive */
@media (max-width:820px){
  .ayk-ab{padding:50px 15px}
  /* .ayk-ab .ayk-ab-box{grid-template-columns:1fr;padding:28px 20px 36px} */
    .ayk-ab .ayk-ab-box{grid-template-columns:1fr}
  .ayk-ab .ayk-ab-br{display:none}

  .ayk-ab .ayk-ab-left,.ayk-ab .ayk-ab-card{grid-column:1}
  .ayk-ab a.ayk-ab-btn-outline,.ayk-ab a.ayk-ab-btn-fill{min-width:0;flex:1 1 100%}
}
@media (max-width:520px){
  .ayk-ab .ayk-ab-logos{grid-template-columns:repeat(2,1fr)}
  .ayk-ab .ayk-ab-card-title{font-size:21px}
}



/* ===== ABOUT SECTION: DESKTOP DEFAULTS FOR NEW ELEMENTS ===== */
.ayk-ab .ayk-ab-eyebrow{display:none}
.ayk-ab .ayk-ab-logo-lbl{display:none}

/* ===== ABOUT SECTION: MOBILE ONLY (matches screenshot) ===== */
@media (max-width:820px){

  .ayk-ab{
    padding:26px 14px 34px;
    background:linear-gradient(180deg,#ffffff 0%,#eef5fd 100%);
  }

  .ayk-ab .ayk-ab-box{row-gap:16px}

  /* eyebrow */
  .ayk-ab .ayk-ab-eyebrow{
    display:flex;align-items:center;gap:8px;margin:0;
    font-size:10.5px;font-weight:700;letter-spacing:.4px;
    color:var(--ab-navy);text-transform:uppercase;line-height:1.2;
  }
  .ayk-ab .ayk-ab-eyebrow::before{
    content:"";width:26px;height:3px;background:var(--ab-red);border-radius:2px;flex:none;
  }

  /* title */
  .ayk-ab .ayk-ab-title{
    margin:10px 0 0;
    font-size:22px;line-height:1.2;font-weight:800;letter-spacing:-.3px;
  }
  .ayk-ab .ayk-ab-br{display:none}
  .ayk-ab .ayk-ab-rule{display:none}

  /* paragraphs */
  .ayk-ab .ayk-ab-left p{
    font-size:13px;line-height:1.5;margin:0 0 10px;
  }

  /* buttons: full width stacked */
  .ayk-ab .ayk-ab-btns{
    flex-direction:column;gap:10px;margin-top:14px;
  }
  .ayk-ab a.ayk-ab-btn-outline,
  .ayk-ab a.ayk-ab-btn-fill{
    width:100%;min-width:0;flex:none;height:40px;
    font-size:11.5px;border-radius:8px;gap:8px;
  }
  .ayk-ab a.ayk-ab-btn-outline{border-width:1.5px}
  .ayk-ab .ayk-ab-btn svg{width:16px;height:16px}
  .ayk-ab a.ayk-ab-btn-fill svg:last-child{width:12px;height:12px}

  /* certificate card */
  .ayk-ab .ayk-ab-card{
    border-radius:16px;
    background:#fff;
    box-shadow:0 6px 22px rgba(30,60,120,.14);
    margin-top:6px;
  }
  .ayk-ab .ayk-ab-card-head{
    gap:12px;padding:14px 16px;
    background:linear-gradient(135deg,#dfeafb,#eef4fd);
  }
  .ayk-ab .ayk-ab-card-head svg{width:32px;height:32px}
  .ayk-ab .ayk-ab-card-head .ayk-ab-bar{width:1.5px}
  .ayk-ab .ayk-ab-card-title{font-size:15px;line-height:1.2}

  .ayk-ab .ayk-ab-checks{padding:2px 16px 0}
  .ayk-ab .ayk-ab-checks li{
    gap:10px;padding:8px 0;font-size:11px;line-height:1.3;
  }
  .ayk-ab .ayk-ab-checks li::before{
    width:15px;height:15px;background-size:9px;
  }

  .ayk-ab .ayk-ab-certified{
    margin:6px 16px 10px;padding-top:10px;gap:10px;
    font-size:11px;letter-spacing:1.2px;
  }

  /* logos: 2x2 with labels */
  .ayk-ab .ayk-ab-logos{
    grid-template-columns:repeat(2,1fr);
    gap:10px;padding:0 14px 16px;
  }
  .ayk-ab .ayk-ab-logo{
    height:auto;flex-direction:column;gap:6px;
    padding:12px 8px 10px;border-radius:12px;
    box-shadow:0 2px 10px rgba(30,60,120,.12);
  }
  .ayk-ab .ayk-ab-logo img{max-height:52px;width:auto}
  .ayk-ab .ayk-ab-logo-lbl{
    display:block;text-align:center;
    font-size:9px;font-weight:700;line-height:1.25;
    color:var(--ab-navy);text-transform:uppercase;letter-spacing:.2px;
  }
}

/* very small phones */
@media (max-width:380px){
  .ayk-ab .ayk-ab-title{font-size:20px}
  .ayk-ab .ayk-ab-left p{font-size:11px}
}


@media (max-width:820px){

  .ayk-ab{
    width:100%;
    max-width:100%;
    margin:0;
    padding:26px 14px 34px;
    overflow-x:hidden;      /* strip / sideways shift rokta hai */
  }

  .ayk-ab .ayk-ab-box{
    width:100%;
    max-width:100%;
    margin:0 auto;
    padding:0;
    grid-template-columns:minmax(0,1fr);  /* 1fr ki jagah */
    column-gap:0;
    row-gap:16px;
  }

  .ayk-ab .ayk-ab-head,
  .ayk-ab .ayk-ab-left,
  .ayk-ab .ayk-ab-card{
    grid-column:1 / -1;
    width:100%;
    max-width:100%;
    min-width:0;
    margin-left:0;
    margin-right:0;
  }
}
</style>

<!-- <script>
(function () {
    'use strict';

    var section = document.querySelector('.ayk-se');
    if (!section) return;

    var prefersReducedMotion = window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function loadImages(root) {
        if (!root) return;
        root.querySelectorAll('img[data-src]').forEach(function (img) {
            var src = img.getAttribute('data-src');
            if (!src || img.getAttribute('data-loaded') === '1') return;
            img.setAttribute('data-loaded', '1');
            img.src = src;
            img.removeAttribute('data-src');
        });
    }

    var feature = section.querySelector('.ayk-se-feature-photo');
    var gallery = section.querySelector('.ayk-se-gallery');
    var track = document.getElementById('aykSeTrack');

    function startFeatureRotation() {
        if (!feature || prefersReducedMotion) return;
        var imgs = feature.querySelectorAll('img');
        if (imgs.length < 2) return;

        var i = 0;
        window.setInterval(function () {
            imgs[i].classList.remove('ayk-se-active');
            i = (i + 1) % imgs.length;
            imgs[i].classList.add('ayk-se-active');
        }, 4500);
    }

    function setupGalleryLoop() {
        if (!track || track.dataset.loopReady === '1') return;

        var originalCards = Array.prototype.slice.call(track.children);
        originalCards.forEach(function (card) {
            track.appendChild(card.cloneNode(true));
        });

        function calculateLoop() {
            var singleSetWidth = 0;
            for (var j = 0; j < originalCards.length; j++) {
                singleSetWidth += track.children[j].getBoundingClientRect().width;
            }

            var gap = parseFloat(getComputedStyle(track).gap) || 0;
            singleSetWidth += gap * originalCards.length;
            track.style.setProperty('--ayk-se-loop', '-' + singleSetWidth + 'px');
            track.style.animationDuration = (singleSetWidth / 32) + 's';
            if (!prefersReducedMotion) track.classList.add('ayk-se-anim');
        }

        track.dataset.loopReady = '1';

        if (document.fonts && document.fonts.ready) {
            document.fonts.ready.then(calculateLoop);
        } else {
            calculateLoop();
        }

        window.addEventListener('resize', calculateLoop, { passive: true });
    }

    function activate() {
        loadImages(feature);
        loadImages(gallery);
        setupGalleryLoop();
        startFeatureRotation();
    }

    if ('IntersectionObserver' in window) {
        var observer = new IntersectionObserver(function (entries, obs) {
            if (entries.some(function (entry) { return entry.isIntersecting; })) {
                obs.disconnect();
                activate();
            }
        }, { rootMargin: '250px 0px' });

        observer.observe(section);
    } else {    
        window.addEventListener('load', activate, { once: true });
    }
})();
</script> -->

<style>
    /* --- INFO SEC BACKGROUND & PERFECT BLEND --- */
    .info-sec {
        /* Original Background Image */
        background: url('img/government-certified.webp') center center / cover no-repeat !important;
        
        /* Blending ke liye position relative zaroori hai */
        position: relative;
    }

    /* 1. Yeh gradient shadow upar wale dark blue section se match karegi */
    .info-sec::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 50px; /* Fade ki height (ishko kam ya zyada kar sakte hain) */
        
        /* #05447D wohi dark blue hai jo upar wale section (.ss) ka base color hai */
        background: linear-gradient(to bottom, #05447D 0%, rgba(5, 68, 125, 0) 100%);
        
        pointer-events: none; /* Taake text select karne mein masla na ho */
        z-index: 1;
    }

    /* 2. Yeh text ko shadow ke upar (crisp) rakhega */
    .info-sec .info-wrap {
        position: relative;
        z-index: 2;
    }
</style>

<section class="info-sec">

    <div class="info-wrap">

        <div class="info-left">

            <h3 style="font-size: 30px; font-weight: 600;">
                Government Licensed Overseas Recruitment Agency in Pakistan
            </h3>

            <p style="font-size: 16px; color: #000000;">
    Overseas employers and HR managers looking for a trusted 
   <strong><a href="https://ayk.global/request-manpower-for-your-project.php" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important; box-shadow:none !important;">manpower recruitment services from Pakistan</a></strong>
    can rely on AYK Overseas Recruitment &amp; HR Manpower Agency for skilled, semi-skilled and unskilled Pakistani manpower.
</p>

<p style="font-size: 16px; color: #000000;">
    We provide overseas recruitment, manpower recruitment and staffing solutions
    for international employers across Saudi Arabia, the UAE, Qatar, Kuwait,
    Europe and other global markets.
</p>

<p style="font-size: 16px; color: #000000;">
    AYK is a <strong><a href="https://ayk.global/our-license.php" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">government-licensed overseas employment agency in Pakistan</a></strong>,
    providing reliable manpower sourcing, candidate screening, <strong><a href="https://ayk.global/trade-testing.php" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">trade testing recruitment</a></strong> support and workforce solutions for businesses.
</p>

            <div class="info-buttons">
                <a href="https://ayk.global/our-license.php">LEGAL STATUS</a>
                <a href="https://ayk.global/contact">CONTACT US</a>
            </div>

        </div>


        <div class="info-right">

            <h3 style="font-size: 30px; font-weight: 600;">
               Overseas Recruitment & HR Staffing Solutions from Pakistan
            </h3>

            <p style="font-size: 16px; color: #000000;">
                International employers can outsource their recruitment requirements to
                AYK by sharing their workforce needs. Our recruitment process helps
                companies source qualified professionals and reliable manpower for
                international projects.
            </p>

            <ul>
    <li style="font-size: 14px; color: #000000;">
    <strong>
        <a href="https://ayk.global/profession.php"
           style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">
            Professional &amp; Technical Manpower Recruitment
        </a>
    </strong>
</li>

    <li style="font-size: 14px; color: #000000;">
    <strong><a href="https://ayk.global/industry/construction-manpower-services" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">Construction Manpower Recruitment</a></strong>
</li>
       <li style="font-size: 14px; color: #000000;">
    <strong><a href="https://ayk.global/industry/oil-gas-manpower-recruitment" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">Oil &amp; Gas Manpower Recruitment</a></strong>
</li>

    <li style="font-size: 14px; color: #000000;">
        Skilled &amp; Semi-Skilled Pakistani Workers
    </li>

    <li style="font-size: 14px; color: #000000;">
    <strong><a href="https://ayk.global/request-manpower-for-your-project.php" style="color:#003a66 !important; text-decoration:none !important; border-bottom:none !important;">Bulk Manpower Recruitment &amp; Project Hiring</a></strong>
</li>
</ul>
        </div>

    </div>

</section>



<section class="industries">

    <div class="container">

     
       <h3 style="font-size: 32px; font-weight: 600;">Global Recruitment &amp; Manpower Services by Industry</h3>
        <p class="sub" style="font-size: 16px !important; color: #000000 !important;">
    AYK provides skilled, semi-skilled and unskilled
    <strong>
        <a href="https://ayk.global/request-manpower-for-your-project.php">
            manpower recruitment services from Pakistan
        </a>
    </strong>
    for employers across major industries. Our global recruitment and staffing solutions cover construction, oil &amp; gas, healthcare, medical staff, manufacturing, facility management, IT, engineering, logistics, aviation, marine, telecommunications, administration, education and other workforce sectors across the GCC, Europe and international markets. We support permanent, temporary and contract staffing, bulk manpower recruitment and project-based workforce requirements with reliable candidate sourcing and deployment.
</p>

     <div class="industries-grid">

            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/Industrial-Labour-2.webp" alt="Skilled Construction Workers and Engineers for Overseas Projects" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/construction-manpower-services"><span>Construction &amp; Infrastructure Manpower Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/Oil-Gas-Staffing-Agency-in-Pakistan-For-Overseas-Employers.webp" alt="Hire Oil & Gas Manpower from AYK Overseas" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/oil-gas-manpower-recruitment"><span>Oil &amp; Gas &amp; Energy Manpower Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/helathcare-doctors.webp" alt="Healthcare recruitment for doctors and nurses" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/healthcare-medical-recruitment"><span>Healthcare &amp; Medical Staff Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/it-digital.webp" alt="IT recruitment and staffing services" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/it-staffing-services"><span>IT, Digital &amp; Technology Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/office-staff-corpaorate-sector.webp" alt="Office staffing and recruitment services" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/office-staff-manpower-services"><span>Administration, Office &amp; Corporate Staffing</span></a></div>

            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/manufacturing-industrial-workforce.webp" alt="ayk overseas provides industrial workers for Saudi Arabia, Qatar, Kuwait, UAE, Europe" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/manufacturing-manpower-services"><span>Manufacturing &amp; Industrial Manpower Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/aviation-airport-staff.webp" alt=" Best HR Manpower Agency for Airport Sector Recruitment" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/aviation-manpower-services"><span>Aviation &amp; Airport Staff Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/marine-shiipping-sector.webp" alt="Hire Now manpower for Your Marine Projects" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/marine-manpower-services"><span>Marine, Shipping &amp; Port Operations Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/telecomunication-sector.webp" alt="Best Telecom industry workers providers in Pakistan" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/telecom-manpower-services"><span>Telecommunications &amp; Customer Support Recruitment</span></a></div>
            <div class="industry-card"><img src="img/recuritment-sectros-by-industry/education-tranning-staff.webp" alt="Top HR Manpower Agency in pakistan provides staffing solutions in education sector" loading="lazy" decoding="async" fetchpriority="low" width="800" height="150"><a href="https://ayk.global/industry/education-manpower-services"><span>Education, Training &amp; Academic Recruitment</span></a></div>

        </div>

     
        <div class="view-more-wrap">
            <a href="https://ayk.global/recruitment-by-industry.php" class="view-more-btn">View More Industries</a>
        </div>

    </div>

</section>

 <section class="process">
    <div class="container">
        <h3 class="process-title">Our Overseas Recruitment Process for International Employers</h3>

        <div class="process-steps">

            <div class="step">
                <div class="circle"><i class="fas fa-comments"></i></div>
                <p>Requirement Analysis</p>
            </div>

            <div class="step">
                <div class="circle"><i class="fas fa-user-tie"></i></div>
                <p>Candidate Sourcing</p>
            </div>

            <div class="step">
                <div class="circle"><i class="fas fa-clipboard-check"></i></div>
                <p>Candidate Screening</p>
            </div>

            <div class="step">
                <div class="circle"><i class="fas fa-user-check"></i></div>
                <p>Shortlisting & Interviews</p>
            </div>

            <div class="step">
                <div class="circle"><i class="fas fa-tasks"></i></div>
                <p>Trade Testing & Selection</p>
            </div>

            <div class="step">
                <div class="circle"><i class="fas fa-file-medical"></i></div>
                <p>Documentation & Medical</p>
            </div>
            
            <div class="step">
                <div class="circle"><i class="fas fa-passport"></i></div>
                <p>Visa Processing & Approval</p>
            </div>
            
            <div class="step">
                <div class="circle"><i class="fas fa-plane-departure"></i></div>
                <p>Workforce Deployment</p>
            </div>

        </div>
    </div>
</section>

        


<!-- Countries we recruit for Section -->



<!-- ===================================================
     COUNTRIES WE RECRUIT FOR — Unified Slider
     =================================================== -->
<style>
/* ===== SHELL (Prominent Brand Theme) ===== */
/* ===== SHELL (Prominent Brand Theme with BG Image) ===== */
.countries-partners{
  position: relative;
  overflow: hidden;
  padding: 70px 24px 90px;
  text-align: center;
  background: #061636; /* Fallback color */
  border-top: 5px solid rgba(250, 219, 141, 0.8);
  border-bottom: 5px solid rgba(224, 36, 84, 0.4);
  border-radius: 4px;
}

/* 1. Background Image Layer (Zyada roshan aur clear) */
.countries-partners::before {
  content: "";
  position: absolute;
  inset: 0;
  background: url('img/Global Recruitment Connections.png') center center / cover no-repeat;
  opacity: 1; /* 0.7 se barha kar 0.85 kiya taake image aur clear ho */
  filter: blur(1px); /* Blur aur kam kar diya */
  z-index: 0;
}

/* 2. Overlay Layer (Bilkul halka tint) */
.countries-partners::after {
  content: "";
  position: absolute;
  inset: 0;
  background:
    /* Dark tint ko aur kam kar diya (0.4/0.5 se 0.2/0.3) */
    linear-gradient(180deg, rgba(6, 22, 54, 0.6) 0%, rgba(11, 46, 89, 0.3) 100%),
    
    /* Aapke purane ambient glows (Yeh waise hi rahenge) */
    radial-gradient(ellipse 60% 50% at 50% 0%, rgba(250, 219, 141, 0.45), transparent 50%),
    radial-gradient(ellipse 60% 60% at 0% 100%, rgba(16, 85, 150, 0.6), transparent 70%),
    radial-gradient(ellipse 60% 60% at 100% 100%, rgba(11, 99, 206, 0.4), transparent 70%);
  z-index: 1;
  pointer-events: none;
}

.countries-partners .glow{
  --d: clamp(500px, 55vw, 1100px);
  position: absolute;
  width: var(--d); height: var(--d);
  bottom: calc(var(--d) * -.86);
  border-radius: 50%;
  pointer-events: none; z-index: 2;
}
/* Left Curve - Gold / Yellow with Increased Glow */
.countries-partners .glow.b{
  left: calc(var(--d) * -.57);
  border: 2px solid rgba(255,210,90,.9); /* Gold */
  box-shadow:
    inset 0 0 80px 10px rgba(245,184,0,.5), /* Glow increased */
    inset 0 0 12px 2px rgba(255,210,90,.9),
    0 0 60px 8px rgba(255,171,30,.4);
}
/* Right Curve - Red (Kept as is) */
.countries-partners .glow.g{
  right: calc(var(--d) * -.57);
  border: 2px solid rgba(224,36,84,.85);
  box-shadow:
    inset 0 0 60px 5px rgba(200,16,46,.36),
    inset 0 0 8px 1px rgba(255,110,140,.7),
    0 0 40px 4px rgba(224,36,84,.28);
}
.countries-partners .inner{
  position: relative; z-index: 3;
  max-width: 1400px; margin: 0 auto;
}

/* ===== BADGE ROW ===== */
.countries-partners .badge-row{
  display: flex; align-items: center; justify-content: center;
  gap: 12px; margin-bottom: 20px;
}
.countries-partners .badge-row .line{
  width: 52px; height: 2px; border-radius: 3px;
}
.countries-partners .badge-row .line.l{ background: linear-gradient(90deg, transparent, #FDBB30); } /* Brand Red */
.countries-partners .badge-row .line.r{ background: linear-gradient(90deg, #3784e2, transparent); } /* Brand Blue */
.countries-partners .badge{
  padding: 9px 18px; border-radius: 999px;
  font-size: 12px;
  font-family: 'Poppins', sans-serif;
  font-weight: 600; letter-spacing: .28em;
  text-transform: uppercase;
  color: #cfd6e6;
  border: 1.5px solid transparent;
  background:
    linear-gradient(#010b33,#010b33) padding-box,
    linear-gradient(90deg, #FADB8D, #0b63ce) border-box; /* Red & Blue border */
}

/* ===== HEADING ===== */
.countries-partners h2{
  font-size: clamp(28px, 4vw, 46px);
  font-weight: 700; line-height: 1.1;
  color: #fff; letter-spacing: -0.01em;
  margin: 0;
}
/* Heading - Removed Red, used pure Gold/Yellow */
/* .countries-partners h2 span{
  background: linear-gradient(90deg, #ffd23f 0%, #ffab1e 50%, #f5b800 100%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
} */
.countries-partners h2 span{
  /* Light Cream / Soft Gold Gradient */
  background: linear-gradient(90deg, #ebd89b 0%, #FADB8D 50%, #F5C86B 100%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  
  /* Ek bohat halka sa glow dene ke liye (optional but looks premium) */
  /* filter: drop-shadow(0 0 15px rgba(250, 219, 141, 0.3));     */
}

.countries-partners .sub{
  max-width: 580px;
  margin: 16px auto 30px;
  font-size: 15px; line-height: 1.65;
  color: #fff;
}

/* ===== CAPSULE MARQUEE ===== */
.countries-partners .track-wrap{
  position: relative;
  margin: 0 auto;
  max-width: 100%;
}
.countries-partners .partners-capsule{
  position: relative;
  overflow: hidden;
  border-radius: 999px;
  border: 1px solid rgba(255,210,90,.4); /* Gold */
  border-bottom-color: rgba(255,171,30,.8); /* Gold */
  background: linear-gradient(180deg, rgba(0,58,102,.4), rgba(1,11,51,.6));
  box-shadow: 0 15px 40px rgba(0,0,0,0.4), inset 0 0 20px rgba(255,171,30,0.15); /* Gold inner glow */
}

.countries-partners .track{
  display: flex; align-items: center;
  gap: 16px;
  padding: 18px 70px;
  width: max-content;
  animation: cpScroll 60s linear infinite;
  will-change: transform;
}
@keyframes cpScroll{
  from{ transform: translateX(0); }
  to  { transform: translateX(-50%); }
}
@media (prefers-reduced-motion: reduce){
  .countries-partners .track{ animation: none; }
}

/* ===== SIDE RINGS ===== */
.countries-partners .ring{
  position: absolute;
  top: 0; height: 100%;
  aspect-ratio: 1 / 2;
  z-index: 2;
  pointer-events: none;
  overflow: visible;
}
.countries-partners .ring.l{ left: 0; }
.countries-partners .ring.r{ right: 0; transform: scaleX(-1); }
.countries-partners .ring .blue{ filter: drop-shadow(0 0 5px rgba(11,99,206,.9)); }
.countries-partners .ring .gold{ filter: drop-shadow(0 0 6px rgba(224,36,84,.7)); } /* Changed to Red */

/* ===== FLAG CARD ===== */
.countries-partners .flag-item{
  flex: 0 0 auto;
  height: 80px;
  display: flex; align-items: center;
  gap: 14px;
  padding: 0 22px;
  border-radius: 12px;
  color: #dfe5f2;
  font-size: 16px; font-weight: 600;
  font-family: 'Poppins', sans-serif;
  background: linear-gradient(180deg, rgba(0,58,102,.5), rgba(1,11,51,.7));
  border: 1px solid rgba(11,99,206,.3);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.05);
  white-space: nowrap;
  text-decoration: none;
  transition: transform .3s ease, border-color .3s ease, box-shadow .3s ease, background .3s ease;
}
/* Flag Card Hover - Gold Border */
.countries-partners .flag-item:hover{
  transform: translateY(-3px);
  border-color: rgba(250, 219, 141, 0.8); /* Gold Hover */
  background: linear-gradient(180deg, rgba(0,58,102,.8), rgba(1,11,51,.9));
  box-shadow: 0 12px 26px -10px rgba(255,171,30,.6); /* Gold shadow */
}
.countries-partners .flag-item img{
  width: 48px; height: 48px;
  border-radius: 50%;
  object-fit: cover;
  flex-shrink: 0;
  box-shadow: 0 6px 14px rgba(0,0,0,.35);
  border: 2px solid rgba(11,99,206,.5);
  background: #0a0f2b;
  transition: border-color .3s ease;
}
.countries-partners .flag-item:hover img{
   border-color: rgba(250, 219, 141, 0.8);;
}

/* ===== VIEW ALL BUTTON (Prominent) ===== */
.countries-partners .cp-view-all{
  display: inline-flex; align-items: center; gap: 10px;
  margin-top: 44px;
  padding: 15px 36px;
  background: linear-gradient(135deg, #e02454, #c8102e);
  color: #fff; text-decoration: none;
  font-family: 'Poppins', sans-serif;
  font-size: 16px; font-weight: 700;
  border-radius: 30px;
  transition: all .3s ease;
  position: relative; z-index: 2;
  box-shadow: 0 10px 25px -5px rgba(224,36,84,.6);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.countries-partners .cp-view-all:hover{
  transform: translateY(-4px) scale(1.02);
  box-shadow: 0 18px 35px -5px rgba(224,36,84,.8);
  background: linear-gradient(135deg, #f02d5f, #e02454);
}

/* ===== RESPONSIVE ===== */
@media (max-width: 1024px){
  .countries-partners{ padding: 56px 20px 70px; }
  .countries-partners h2{ font-size: clamp(26px, 5vw, 38px); }
  .countries-partners .sub{ font-size: 14px; }
  .countries-partners .track{ padding: 16px 56px; gap: 14px; }
  .countries-partners .flag-item{ height: 70px; font-size: 14px; padding: 0 16px; }
  .countries-partners .flag-item img{ width: 42px; height: 42px; }
}
@media (max-width: 720px){
  .countries-partners{ padding: 46px 16px 60px; }
  .countries-partners .badge{ font-size: 10.5px; padding: 8px 14px; letter-spacing: .22em; }
  .countries-partners .badge-row .line{ width: 36px; }
  .countries-partners h2{ font-size: clamp(22px, 7vw, 32px); }
  .countries-partners .sub{ font-size: 13px; max-width: 440px; }
  .countries-partners .track{ padding: 14px 44px; gap: 12px; animation-duration: 45s; }
  .countries-partners .ring{ display: none; }
  .countries-partners .flag-item{ height: 60px; font-size: 13px; padding: 0 14px; gap: 10px; }
  .countries-partners .flag-item img{ width: 36px; height: 36px; }
  .countries-partners .cp-view-all{ padding: 12px 26px; font-size: 13.5px; }
}
@media (max-width: 420px){
  .countries-partners{ padding: 40px 14px 54px; }
  .countries-partners .track{ padding: 12px 36px; }
  .countries-partners .flag-item{ height: 54px; font-size: 12px; }
  .countries-partners .flag-item img{ width: 32px; height: 32px; }
}
</style>

<section class="countries-partners" aria-label="Countries We Recruit For">
  <i class="glow b"></i><i class="glow g"></i>
  <div class="inner">

    <div class="badge-row">
      <span class="line l"></span>
      <span class="badge">TRUSTED WORLDWIDE</span>
      <span class="line r"></span>
    </div>

    <h2>Countries We <span>Recruit For</span></h2>
    <p class="sub">We recruit skilled Pakistani manpower for leading international markets across GCC, Europe and beyond.</p>

    <!-- ===== UNIFIED SLIDER ===== -->
    <div class="track-wrap">
      <div class="partners-capsule">
        <div class="track">
          
          <!-- ===== SET 1 (All 18 Countries) ===== -->
          <a href="recruitment-agency-in-pakistan-for-saudi-arabia.php" class="flag-item">
            <img src="img/recruitment-countries/Saudia-Arabia.jpg" alt="Saudi Arabia" loading="lazy" decoding="async" width="48" height="48">
            <span>Saudi Arabia</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-uae.php" class="flag-item">
            <img src="img/recruitment-countries/UAE.jpg" alt="UAE" loading="lazy" decoding="async" width="48" height="48">
            <span>UAE</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-qatar.php" class="flag-item">
            <img src="img/recruitment-countries/Qatar.jpg" alt="Qatar" loading="lazy" decoding="async" width="48" height="48">
            <span>Qatar</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-oman.php" class="flag-item">
            <img src="img/recruitment-countries/Oman_AYK.webp" alt="Oman" loading="lazy" decoding="async" width="48" height="48">
            <span>Oman</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-kuwait.php" class="flag-item">
            <img src="img/recruitment-countries/Kuwait.jpg" alt="Kuwait" loading="lazy" decoding="async" width="48" height="48">
            <span>Kuwait</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-bahrain.php" class="flag-item">
            <img src="img/recruitment-countries/Bahrain.jpg" alt="Bahrain" loading="lazy" decoding="async" width="48" height="48">
            <span>Bahrain</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-poland.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Poland_AYK.webp" alt="Poland" loading="lazy" decoding="async" width="48" height="48">
            <span>Poland</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-germany.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Germany.webp" alt="Germany" loading="lazy" decoding="async" width="48" height="48">
            <span>Germany</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-romania.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Romania_AYK.webp" alt="Romania" loading="lazy" decoding="async" width="48" height="48">
            <span>Romania</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-netherland.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Netherland_AYK.webp" alt="Netherlands" loading="lazy" decoding="async" width="48" height="48">
            <span>Netherlands</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-ireland.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Ireland.webp" alt="Ireland" loading="lazy" decoding="async" width="48" height="48">
            <span>Ireland</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-spain.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Spain_AYK.webp" alt="Spain" loading="lazy" decoding="async" width="48" height="48">
            <span>Spain</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-canada.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Canada_AYK.webp" alt="Canada" loading="lazy" decoding="async" width="48" height="48">
            <span>Canada</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-uk.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/UK_AYK.webp" alt="UK" loading="lazy" decoding="async" width="48" height="48">
            <span>UK</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-usa.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/USA_AYK.webp" alt="USA" loading="lazy" decoding="async" width="48" height="48">
            <span>USA</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-hong-kong.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Hong Kong_AYK.webp" alt="Hong Kong" loading="lazy" decoding="async" width="48" height="48">
            <span>Hong Kong</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-australia.php" class="flag-item">
            <img src="img/recruitment-countries/Australia_AYK.webp" alt="Australia" loading="lazy" decoding="async" width="48" height="48">
            <span>Australia</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-japan.php" class="flag-item">
            <img src="img/recruitment-by-region-flags/Japan_AYK.webp" alt="Japan" loading="lazy" decoding="async" width="48" height="48">
            <span>Japan</span>
          </a>

          <!-- ===== SET 2 (Duplicate for seamless loop) ===== -->
          <a href="recruitment-agency-in-pakistan-for-saudi-arabia.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Saudia-Arabia.jpg" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Saudi Arabia</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-uae.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/UAE.jpg" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>UAE</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-qatar.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Qatar.jpg" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Qatar</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-oman.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Oman_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Oman</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-kuwait.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Kuwait.jpg" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Kuwait</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-bahrain.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Bahrain.jpg" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Bahrain</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-poland.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Poland_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Poland</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-germany.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Germany.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Germany</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-romania.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Romania_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Romania</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-netherland.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Netherland_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Netherlands</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-ireland.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Ireland.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Ireland</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-spain.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Spain_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Spain</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-canada.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Canada_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Canada</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-uk.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/UK_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>UK</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-usa.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/USA_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>USA</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-hong-kong.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Hong Kong_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Hong Kong</span>
          </a>
          <a href="recruitment-agency-in-pakistan-for-australia.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-countries/Australia_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Australia</span>
          </a>
          <a href="https://ayk.global/recruitment-agency-for-japan.php" class="flag-item" tabindex="-1" aria-hidden="true">
            <img src="img/recruitment-by-region-flags/Japan_AYK.webp" alt="" loading="lazy" decoding="async" width="48" height="48">
            <span>Japan</span>
          </a>

        </div>
      </div>

      <!-- LEFT RING -->
      <svg class="ring l" viewBox="0 0 100 200" fill="none" aria-hidden="true">
        <defs>
  <linearGradient id="cpbl" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#3b82f6" stop-opacity=".25"/> <!-- Sky Blue -->
    <stop offset=".3" stop-color="#3b82f6"/>
    <stop offset=".7" stop-color="#3b82f6"/>
    <stop offset="1" stop-color="#3b82f6" stop-opacity=".25"/>
  </linearGradient>
  <linearGradient id="cpgl" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#3b82f6"/>
    <stop offset=".3" stop-color="#ffd23f"/> <!-- Gold/Yellow -->
    <stop offset=".7" stop-color="#f5b800"/>
    <stop offset="1" stop-color="#3b82f6"/>
  </linearGradient>
</defs>
<path class="blue" d="M100 1.2A98.8 98.8 0 0 0 100 198.8" stroke="url(#cpbl)" stroke-width="2.4" stroke-linecap="round"/>
<path class="gold" d="M48 30A86 86 0 0 0 48 170" stroke="url(#cpgl)" stroke-width="5.5" stroke-linecap="round"/>
      </svg>

      <!-- RIGHT RING -->
      <svg class="ring r" viewBox="0 0 100 200" fill="none" aria-hidden="true">
      <defs>
  <linearGradient id="cpbr" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#3b82f6" stop-opacity=".25"/>
    <stop offset=".3" stop-color="#3b82f6"/>
    <stop offset=".7" stop-color="#3b82f6"/>
    <stop offset="1" stop-color="#3b82f6" stop-opacity=".25"/>
  </linearGradient>
  <linearGradient id="cpgr" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#3b82f6"/>
    <stop offset=".3" stop-color="#ffd23f"/> <!-- Red -->
    <stop offset=".7" stop-color="#f5b800"/>
    <stop offset="1" stop-color="#3b82f6"/>
  </linearGradient>
</defs>
<path class="blue" d="M100 1.2A98.8 98.8 0 0 0 100 198.8" stroke="url(#cpbr)" stroke-width="2.4" stroke-linecap="round"/>
<path class="gold" d="M48 30A86 86 0 0 0 48 170" stroke="url(#cpgr)" stroke-width="5.5" stroke-linecap="round"/>
      </svg>

    </div>

    <a href="recruitment-by-region.php" class="cp-view-all">View All 50+ Countries →</a>

  </div>
</section>


<!-- Countries we recruit for Section End -->



        <!-- <section class="countries-sec">

    <div class="countries-container">

        <h3 style="font-size: 32px; font-weight: 600;">Countries We Recruit For</h3>

   
        <div class="countries-tabs">
            <button class="tab-btn active" data-tab="gcc">GCC Countries</button>
            <button class="tab-btn" data-tab="europe">Europe</button>
            <button class="tab-btn" data-tab="global">Global</button>
        </div>

    
        <div class="countries-box">

            
              <div class="tab-content active" id="gcc">
                <div class="flags-grid">
                    <div><img src="img/recruitment-countries/Saudia-Arabia.jpg" alt="best hr and recruitment agency in pakistan for saudi arabia" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-saudi-arabia.php"><span>Saudi Arabia</span></a></div>
                    <div><img src="img/recruitment-countries/UAE.jpg" alt="top hr and recruitment agency in pakistan for united arab emirates" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-uae.php"><span>UAE</span></a></div>
                    <div><img src="img/recruitment-countries/Qatar.jpg" alt="best hr and manpower agency in pakistan for qatar" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-qatar.php"><span>Qatar</span></a></div>
                    <div><img src="img/recruitment-countries/Oman_AYK.webp" alt="leading hr agency in pakistan for oman" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-oman.php"><span>Oman</span></a> </div>
                    <div><img src="img/recruitment-countries/Kuwait.jpg" alt="trusted hr and recruitment agency in pakistan for kuwait" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-kuwait.php"><span>Kuwait</span></a></div>
                    <div><img src="img/recruitment-countries/Bahrain.jpg" alt="Top 1 hr and recruitment agency in pakistan for bahrain" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-bahrain.php"><span>Bahrain</span></a></div>
                </div>
            </div>
            


            <div class="tab-content" id="europe">
                <div class="flags-grid">
                    <div><img src="img/recruitment-by-region-flags/Poland_AYK.webp" alt="best hr and recruitment agency in pakistan for poland" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-poland.php"><span>Poland</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Germany.webp" alt="best hr and recruitment agency in pakistan for Germany" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-germany.php"><span>Germany</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Romania_AYK.webp" alt="best hr and recruitment agency in pakistan for Romania" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-romania.php"><span>Romania</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Netherland_AYK.webp" alt="best hr and recruitment agency in pakistan for Netherlands" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-netherland.php"><span>Netherlands</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Ireland.webp" alt="best hr and recruitment agency in pakistan for Ireland" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-ireland.php"><span>Ireland</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Spain_AYK.webp" alt="hr and recruitment agency in pakistan for spain" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-spain.php"><span>Spain</span></a></div>
                </div>
            </div>

            <div class="tab-content" id="global">
                <div class="flags-grid">
                    <div><img src="img/recruitment-by-region-flags/Canada_AYK.webp" alt="Leading hr and recruitment agency in pakistan for canada" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-canada.php"><span>Canada</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/UK_AYK.webp" alt="one of the best hr and recruitment agency in pakistan for united kingdom" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-uk.php"><span>UK</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/USA_AYK.webp" alt="best and top hr and recruitment agency in pakistan for united states of america" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-usa.php"><span>USA</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Hong Kong_AYK.webp" alt="best hr and recruitment agency in pakistan for hong kong" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-hong-kong.php"><span>Hong Kong</span></a></div>
                    <div><img src="img/recruitment-countries/Australia_AYK.webp" alt="best hr and recruitment agency in pakistan for australia" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="recruitment-agency-in-pakistan-for-australia.php"><span>Australia</span></a></div>
                    <div><img src="img/recruitment-by-region-flags/Japan_AYK.webp" alt="hr and manpower agency in pakistan for japan" loading="lazy" decoding="async" fetchpriority="low" width="70" height="70"><a href="https://ayk.global/recruitment-agency-for-japan.php"><span>Japan</span></a></div>
                </div>
            </div>

        </div>


        <a href="recruitment-by-region.php" class="countries-btn">View All 50+ Countries →</a>

    </div>

</section> -->


<style>
    /* ================= PREMIUM GOLD & NAVY GLASSY WORKFORCE PANEL ================= */

.workforce-wrap {
    align-items: flex-start !important; 
}

/* 1. Light Glassy Main Panel */
.premium-stats-panel {
    flex: 1.2;
    /* Premium Light Glass Background */
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.95), rgba(250, 252, 255, 0.9)) !important;
    backdrop-filter: blur(20px) saturate(150%) !important;
    -webkit-backdrop-filter: blur(20px) saturate(150%) !important;
    
    /* Soft Border & Shadow */
    border: 1px solid rgba(5, 68, 125, 0.08) !important;
    border-radius: 20px !important;
    box-shadow: 0 15px 35px rgba(5, 68, 125, 0.05), inset 0 0 20px rgba(255,255,255,0.8) !important;
    
    padding: 22px !important; 
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
}

/* Subtle Gold Glow (Replaced Green) */
.premium-stats-panel::before {
    content: '';
    position: absolute;
    top: -50px;
    right: -50px;
    width: 250px;
    height: 250px;
    /* Using #FADB8D with opacity for a soft blend */
    background: radial-gradient(circle, rgba(250, 219, 141, 0.35) 0%, transparent 70%);
    border-radius: 50%;
    pointer-events: none;
}

.premium-header {
    margin-bottom: 18px !important; 
    position: relative;
    z-index: 1;
}

.premium-header h3 {
    font-size: 18px !important;
    font-weight: 700;
    color: #05447D !important; /* Navy Blue */
    margin-bottom: 4px;
    letter-spacing: 0.5px;
}

.premium-header p {
    font-size: 12.5px !important;
    color: #64748b !important; /* Muted Gray */
    margin: 0;
}

/* 2. Grid Fixes */
.premium-stats-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px !important; 
    position: relative;
    z-index: 1;
}

/* 3. Premium Cards with Navy & Gold */
.premium-stat-card {
    /* Subtle gradient blend of white and very light gold */
    background: linear-gradient(145deg, #ffffff, #fdfcf8) !important;
    border: 1px solid rgba(5, 68, 125, 0.12) !important; /* Soft Navy Border */
    
    border-radius: 12px;
    padding: 16px 12px !important; 
    display: flex;
    align-items: center;
    gap: 12px !important;
    transition: all 0.3s ease;
    position: relative;
    min-width: 0;
    box-shadow: 0 2px 8px rgba(5, 68, 125, 0.03) !important;
}

/* Hover Effect: Gold Border Glow */
.premium-stat-card:hover {
    background: #ffffff !important;
    border-color: #FDBB30 !important; /* Gold Border */
    transform: translateY(-3px);
    box-shadow: 0 8px 20px rgba(5, 68, 125, 0.06), 0 0 15px rgba(253, 187, 48, 0.2) !important;
}

/* Icons: Light Gold bg with Navy Icon */
.ps-icon {
    width: 32px !important; 
    height: 32px !important;
    background: rgba(253, 187, 48, 0.15) !important; /* Very light gold */
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #05447D !important; /* Navy Blue Icon */
    font-size: 13px !important; 
    flex-shrink: 0;
    transition: 0.3s ease;
}

/* Hover: Solid Gold bg with White Icon */
.premium-stat-card:hover .ps-icon {
    background: #FDBB30 !important; /* Solid Gold */
    color: #ffffff !important;
    box-shadow: 0 0 10px rgba(253, 187, 48, 0.4);
}

.ps-details {
    display: flex;
    flex-direction: column;
    flex-grow: 1;
    min-width: 0; 
}

/* Text Colors */
.ps-name {
    font-size: 11px !important; 
    color: #64748b !important; /* Gray */
    font-weight: 600;
    line-height: 1.2;
    margin-bottom: 2px;
    white-space: normal !important;
    overflow: visible !important;
}

.ps-number {
    font-size: 16px !important;
    font-weight: 800;
    color: #05447D !important; /* Navy Blue */
    line-height: 1;
}

/* Pulsing Dot: Gold */
.ps-dot {
    width: 6px !important;
    height: 6px !important;
    background: #FDBB30 !important; /* Gold Dot */
    border-radius: 50%;
    position: absolute;
    top: 10px;
    right: 10px;
    box-shadow: 0 0 8px #FDBB30;
    animation: psPulseGold 2s infinite;
}

@keyframes psPulseGold {
    0% { box-shadow: 0 0 0 0 rgba(253, 187, 48, 0.7); }
    70% { box-shadow: 0 0 0 6px rgba(253, 187, 48, 0); }
    100% { box-shadow: 0 0 0 0 rgba(253, 187, 48, 0); }
}

/* Mobile Responsiveness */
@media (max-width: 768px) {
    .premium-stats-grid {
        grid-template-columns: 1fr; 
    }
    .premium-stats-panel {
        padding: 18px !important;
    }
    .premium-header h3 {
        font-size: 16px !important;
    }
}
</style>

<section class="workforce-sec" id="request-manpower">

    <div class="workforce-wrap">

        

            <!-- PREMIUM REDESIGNED LEFT PANEL -->
        <div class="workforce-left premium-stats-panel">
            
            <div class="premium-header">
                <h3>Available Skilled Pakistani Workforce</h3>
                <p>Real-time available talent pool</p>
            </div>

            <div class="premium-stats-grid">
                
                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-cogs"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Engineers</span>
                        <span class="ps-number">189</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-user-md"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Doctors / Nurses</span>
                        <span class="ps-number">88</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-truck"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Drivers</span>
                        <span class="ps-number">69</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-motorcycle"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Delivery Riders</span>
                        <span class="ps-number">363</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-hammer"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Carpenter</span>
                        <span class="ps-number">17</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-tools"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Fabricators</span>
                        <span class="ps-number">53</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-wrench"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Auto Mechanics</span>
                        <span class="ps-number">49</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-industry"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Machine Workers</span>
                        <span class="ps-number">56</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-bolt"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Electricians</span>
                        <span class="ps-number">67</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-faucet"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Plumbers</span>
                        <span class="ps-number">33</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-helmet-safety"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Site Laborers</span>
                        <span class="ps-number">279</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

                <div class="premium-stat-card">
                    <div class="ps-icon"><i class="fas fa-fire"></i></div>
                    <div class="ps-details">
                        <span class="ps-name">Welders 6G/TIG</span>
                        <span class="ps-number">43</span>
                    </div>
                    <div class="ps-dot"></div>
                </div>

            </div>
        </div>
        <!-- <div class="workforce-left">
            
            <h3 style="color: #fff">Available Skilled Pakistani Workforce</h3>

            <ul>
                <li><span class="dot"></span> Engineers Ready: <b>189</b></li>
                <li><span class="dot"></span> Doctors / Nurses Ready: <b>88</b></li>
                <li><span class="dot"></span> Drivers Ready: <b>69</b></li>
                <li><span class="dot"></span> Delivery Riders Ready: <b>363</b></li>
                <li><span class="dot"></span> Carpenter Ready: <b>17</b></li>
                <li><span class="dot"></span> Fabricators Ready: <b>53</b></li>
                <li><span class="dot"></span> Auto Mechanics Ready: <b>49</b></li>
                <li><span class="dot"></span> Machine Operators Ready: <b>56</b></li>
                 <li><span class="dot"></span> Electricians Ready: <b>67</b></li>
                <li><span class="dot"></span> Plumbers Ready: <b>33</b></li>
                <li><span class="dot"></span> Construction Site Laborers Ready: <b>279</b></li>
                 <li><span class="dot"></span> Welders 6G/TIG/SMAW/FCAW Ready: <b>43</b></li>
            </ul>
        </div> -->

        
        <div class="workforce-right">

            <h2 class="form-box-title">Hire Pakistani Manpower for Your Project</h2>

     <?php $form_id = 'workforce'; include("includes/manpower-form.php"); ?>

        </div>

    </div>

</section>



<!-- NEW ABOUT SECTION -->

<section class="ayk-ab" aria-labelledby="ayk-ab-title">
  <div class="ayk-ab-box">
 
    <div class="ayk-ab-head">
      <!-- <p class="ayk-ab-eyebrow">About AYK Global</p> -->

      <h2 class="ayk-ab-title" id="ayk-ab-title"><span class="ayk-ab-no">#1</span> Overseas Employment &amp;<br class="ayk-ab-br"> Recruitment Agency in Pakistan</h2>
      <!-- <h2 class="ayk-ab-title" id="ayk-ab-title"><span class="ayk-ab-no">#1</span> Overseas Employment &amp; Recruitment Agency in Pakistan</h2> -->
      <div class="ayk-ab-rule"></div>
    </div>
 
    <div class="ayk-ab-left">
 
      <p>
        AYK Overseas Recruitment &amp; HR Manpower Agency is a licensed Overseas Employment Promoter (OEP) based in Karachi and a leading overseas employment and recruitment agency in Pakistan, providing reliable manpower recruitment, staffing and HR solutions for employers across the GCC, Europe and international markets. We specialize in skilled, semi-skilled and unskilled <strong><a href="https://ayk.global/recruitment-by-region.php">manpower recruitment from Pakistan</a></strong> for international employers and global workforce requirements. Our recruitment solutions help international employers find the right Pakistani talent through reliable overseas recruitment, professional staffing and workforce management services.
      </p>
 
      <p>
        As a trusted manpower recruitment agency and manpower supply company in Pakistan, we help international companies source qualified Pakistani workers and professionals for projects in <a href="recruitment-agency-in-pakistan-for-saudi-arabia.php">Saudi Arabia</a>, the UAE, Qatar, Kuwait, Europe and other overseas markets. We aim to be the best recruitment agency in Pakistan for international employers seeking reliable workforce solutions. Our recruitment services cover candidate sourcing, screening, trade testing, selection, documentation and workforce deployment across different <a href="https://ayk.global/profession.php"><strong>Professions</strong></a>. We provide recruitment and HR manpower solutions for employers hiring skilled, semi-skilled and unskilled workers from Pakistan for international projects.
      </p>
 
      <p>
        Whether you are an overseas employer looking to hire Pakistani manpower or a job seeker searching for <strong><a href="https://ayk.global/latest-overseas-jobs.php">Overseas Job Opportunities</a></strong>, AYK provides structured recruitment and workforce solutions with a focus on quality, compliance and timely deployment.
      </p>
 
      <div class="ayk-ab-btns">
        <a href="https://ayk.global/submit-cv" class="ayk-ab-btn ayk-ab-btn-outline">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>
          I AM A JOB SEEKER
        </a>
        <a href="https://ayk.global/request-manpower-for-your-project.php" class="ayk-ab-btn ayk-ab-btn-fill">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><circle cx="4.8" cy="10" r="2.5"/><circle cx="19.2" cy="10" r="2.5"/><path d="M5.5 20c0-3.6 2.9-5.8 6.5-5.8s6.5 2.2 6.5 5.8z"/></svg>
          START RECRUITING
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>
        </a>
      </div>
 
    </div>
 
    <aside class="ayk-ab-card">
 
      <div class="ayk-ab-card-head">
<svg viewBox="0 0 48 48" aria-hidden="true"><path d="M16 30l-5 15 9-4 4 6 3-12z" fill="#0f1f4d"/><path d="M32 30l5 15-9-4-4 6-3-12z" fill="#0f1f4d"/><circle cx="24" cy="19" r="15" fill="#0f1f4d"/><circle cx="24" cy="19" r="11.5" fill="none" stroke="#fff" stroke-width="1.5" opacity=".85"/><path d="M18 19.5l4.5 4.5 8-9" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span class="ayk-ab-bar"></span>
        <p class="ayk-ab-card-title">Government Certified<br>Recruitment Agency</p>
      </div>
 
      <ul class="ayk-ab-checks">
        <li>Licensed Recruitment Agency (GL-4586/KAR)</li>
        <li>Approved by Ministry of Labor</li>
        <li>Government Certified OEP</li>
        <li>Registered with BEOE</li>
        <li>Member of POEPA</li>
        <li>Approved by Ministry of Foreign Affairs</li>
      </ul>
 
      <p class="ayk-ab-certified">Certified by</p>
 


      <div class="ayk-ab-logos">
  <div class="ayk-ab-logo"><img src="img/g-logos/ISO Logo.webp" alt="government cerified agency in pakistan" loading="lazy" decoding="async" fetchpriority="low"><span class="ayk-ab-logo-lbl">ISO 22000 Certified</span></div>
  <div class="ayk-ab-logo"><img src="img/g-logos/POEPA Logo.webp" alt="government cerified manpower agency in pakistan" loading="lazy" decoding="async" fetchpriority="low"><span class="ayk-ab-logo-lbl">POEPA Member</span></div>
  <div class="ayk-ab-logo"><img src="img/g-logos/ICCI Logo.webp" alt="government cerified hr agency in pakistan" loading="lazy" decoding="async" fetchpriority="low"><span class="ayk-ab-logo-lbl">Government of Pakistan</span></div>
  <div class="ayk-ab-logo"><img src="img/g-logos/UO & HRD Logo.png" alt="government cerified agency who provides manpower for gcc and europe from pakistan" loading="lazy" decoding="async" fetchpriority="low"><span class="ayk-ab-logo-lbl">Overseas Pakistanis &amp; HRD</span></div>
</div>
     
 
    </aside>
 
  </div>
</section>
 
    <!-- <section class="about-sec">

    <div class="about-wrap">

        
        <div class="about-left">

            <h2 style="font-size: 30px; font-weight: 600;"><span>#1 Overseas Employment &amp; Recruitment Agency in Pakistan</span></h2>

            <p style="font-size: 16px !important; color: #000000 !important;">
    AYK Overseas Recruitment & HR Manpower Agency is a licensed Overseas Employment Promoter (OEP) based in Karachi and a leading overseas employment and recruitment agency in Pakistan
    , providing reliable manpower recruitment, staffing and HR solutions for employers across the GCC, Europe and international
    markets. We specialize in skilled, semi-skilled and unskilled <strong><a href="https://ayk.global/recruitment-by-region.php">manpower recruitment from Pakistan</a></strong> for international employers and global workforce requirements. 
    Our recruitment solutions help international employers find the right Pakistani talent through reliable overseas recruitment, professional staffing and workforce management services.
    
</p>

<p style="font-size: 16px !important; color: #000000 !important;">
    As a trusted manpower recruitment agency and manpower supply company in Pakistan,
    we help international companies source qualified Pakistani workers and professionals
    for projects in <a href="recruitment-agency-in-pakistan-for-saudi-arabia.php"><span>Saudi Arabia</span></a>, the UAE, Qatar, Kuwait, Europe and other overseas markets.
    We aim to be the best recruitment agency in Pakistan for international
    employers seeking reliable workforce solutions. Our
recruitment services cover candidate sourcing, screening, trade testing,
selection, documentation and workforce deployment across different
<a href="https://ayk.global/profession.php"><strong>Professions</strong></a>
We provide recruitment and HR manpower solutions for employers hiring skilled, semi-skilled and unskilled workers from Pakistan for international projects.
</p>

<p style="font-size: 16px !important; color: #000000 !important;">
    Whether you are an overseas employer looking to hire Pakistani manpower or a
    job seeker searching for <strong><a href="https://ayk.global/latest-overseas-jobs.php">Overseas Job Opportunities</a></strong>, AYK provides structured
    recruitment and workforce solutions with a focus on quality, compliance and
    timely deployment.
</p>

            <div class="about-buttons">
                <a href="https://ayk.global/submit-cv" class="btn-outline">I AM A JOB SEEKER</a>
                <a href="https://ayk.global/request-manpower-for-your-project.php" class="btn-fill">START RECRUITING</a>
            </div>

        </div>

        
        <div class="about-right">

            
            <p class="cert-section-title" style="font-size: 20px !important; color: #000000 !important;">
    Government Certified Recruitment Agency
</p>

           <ul class="cert-list">
    <li style="font-size: 14px !important; color: #000000 !important;">
        Licensed Recruitment Agency (GL-4586/KAR)
    </li>

    <li style="font-size: 14px !important; color: #000000 !important;">
        Approved by Ministry of Labor
    </li>

    <li style="font-size: 14px !important; color: #000000 !important;">
        Government Certified OEP
    </li>

    <li style="font-size: 14px !important; color: #000000 !important;">
        Registered with BEOE
    </li>

    <li style="font-size: 14px !important; color: #000000 !important;">
        Member of POEPA
    </li>

    <li style="font-size: 14px !important; color: #000000 !important;">
        Approved by Ministry of Foreign Affairs
    </li>
</ul>

<p class="cert-title">
    CERTIFIED BY
</p>

            <div class="cert-logos">
                <img src="img/g-logos/ISO Logo.webp" alt="government cerified agency in pakistan" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/g-logos/POEPA Logo.webp" alt="government cerified manpower agency in pakistan" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/g-logos/ICCI Logo.webp" alt="government cerified hr agency in pakistan" loading="lazy" decoding="async" fetchpriority="low">
                <img src="img/g-logos/UO & HRD Logo.png" alt="government cerified agency who provides manpower for gcc and europe from pakistan" loading="lazy" decoding="async" fetchpriority="low">
            </div>

        </div>

    </div>

</section> -->

<!-- <section class="training-sec" style="width:100%; padding:70px 20px; box-sizing:border-box;">

    <style>
        .training-sec * {}
        

        @media (max-width:768px) {
            .training-sec {
                padding:45px 15px !important;
            }

            .training-wrap {
                flex-direction:column;
                gap:30px;
            }

            .training-left,
            .training-right {
                width:100%;
                flex:100%;
            }

            .training-left h3 {
                font-size:25px !important;
                text-align:center;
            }

            .training-left p {
                font-size:15px !important;
                text-align:left;
            }

            .training-points li {
                font-size:15px !important;
                margin-bottom:10px;
            }

            .training-badges {
                justify-content:center;
                gap:12px;
            }

            .training-badges img {
                max-width:75px;
                max-height:50px;
            }

            .training-btn {
                display:block;
                width:100%;
                text-align:center;
            }

            .training-small {
                grid-template-columns:repeat(2, 1fr);
                gap:10px;
            }

            .training-small img {
                height:135px;
            }
        }

        @media (max-width:400px) {
            .training-left h3 {
                font-size:22px !important;
            }

            .training-small img {
                height:115px;
            }
        }
    </style>

    <div class="training-wrap">

        <div class="training-left">

            <h3 style = "color:white" >AYK Global Training Center for Skilled Workforce &amp; Trade Testing</h3>

            <p style="font-size:16px !important;">
                We provide <strong>
                    <a href="https://ayk.global/trade-testing.php" style="color:red;">
                        professional trade testing
                    </a>
                </strong>, skill development and technical training
                to prepare skilled Pakistani manpower for
                <strong>
                    <a href="https://ayk.global/latest-overseas-jobs.php" style="color:red;">
                        international job requirements
                    </a>
                </strong>
                and global employers.
            </p>

            <ul class="training-points">
                <li>We can conduct up to 200 skilled trade tests per day with a smooth and efficient process.</li>
                <li>State-of-the-Art Technical Training &amp; Skill Development Facilities</li>
                <li>Trade Testing &amp; Skill Certification for Skilled Workforce</li>
                <li>Pakistan &amp; International Deployment-Ready Skilled Workforce</li>
            </ul>

            <div class="training-badges">
                <img src="img/g-logos/ISO Logo.png" alt="Government certified and approved agency in Pakistan" loading="lazy">
                <img src="img/g-logos/POEPA Logo.png" alt="Government certified manpower agency in Pakistan" loading="lazy">
                <img src="img/g-logos/ICCI Logo.png" alt="Government certified HR agency in Pakistan" loading="lazy">
                <img src="img/g-logos/UO & HRD Logo.png" alt="Government certified manpower agency" loading="lazy">
            </div>

            <a href="training.php" class="training-btn">
                Explore Training Center
            </a>

        </div>

        <div class="training-right">

            <div class="training-small">
                <img src="img/trraining-construction.jpeg" alt="Best training center in Pakistan" loading="lazy">
                <img src="img/electrician-training.jpg" alt="AYK Global training center" loading="lazy">
                <img src="img/plumber-training.jpg" alt="Plumber training center" loading="lazy">
                <img src="img/pipefitter-trainig.jpeg" alt="Pipefitter training provider" loading="lazy">
                <img src="img/welder-trainig.jpeg" alt="Certified welder training provider" loading="lazy">
                <img src="img/carpenter-training.jpeg" alt="Carpenter training center" loading="lazy">
            </div>

        </div>

    </div>

</section> -->


<!-- ===================== AYK TRAINING BANNER (drop-in replacement for <section class="training-sec"> ... </section>) ===================== -->
<style>
/* All selectors are scoped to .aykbn so nothing else on the site is affected */
/* .aykbn-outer{width:100%;display:flex;justify-content:center;background:#eaf2fc} */


.aykbn-outer {
    width: 100%;
    display: flex;
    justify-content: center;
    /* Yahan humne top se ek dark blue (#010b33) ka gradient lagaya hai jo 150px tak fade hoga */
    background: linear-gradient(to bottom, #010b33 0%, rgba(1, 11, 51, 0) 40px), #010b33 url(img/bg-img-2.png) center top / cover no-repeat;
}

/* YEH NAYA BLOCK ADD KAREIN */


.aykbn {
    --u: calc(100cqw / 1774);
    position: relative;
    width: 100%;
    max-width: 2400px;
    aspect-ratio: 1774 / 780;
    overflow: hidden;
    container-type: inline-size;
    color: #fff;
    font-family: 'Poppins', Arial, sans-serif;
    background: transparent; 
    z-index: 2; /* YEH ADD KAREIN taake text fade ke ooper dikhe */
}

/* .aykbn-outer {
    width: 100%;
    display: flex;
    justify-content: center;

    background: #010b33 url(img/training-banner-bg.webp) center/cover no-repeat;
}

.aykbn {
    --u: calc(100cqw / 1774);
    position: relative;
    width: 100%;
    max-width: 2400px;      
    aspect-ratio: 1774 / 780;
    overflow: hidden;
    container-type: inline-size;
    color: #fff;
    font-family: 'Poppins', Arial, sans-serif;
    background: transparent; 
} */


.aykbn *{margin:0;padding:0}

/* Everything is positioned in original 1774x887 pixels via --u (1 design px) */
/* .aykbn{--u:calc(100cqw / 1774);position:relative;width:100%;max-width:100%;aspect-ratio:1774/887;overflow:hidden;
 container-type:inline-size;color:#fff;font-family:'Poppins',Arial,sans-serif;text-align:left;text-transform:none;letter-spacing:normal; */
 /* background:#eaf3ff url(img/training-banner-bg.webp) center/cover no-repeat} */
 /* background:#eaf3ff url(img/bg-img-2.png) center/cover no-repeat} */
 /* background:#010b33 url(img/bg-img-2.png) center/cover no-repeat} */

.aykbn .aykbn-a{position:absolute}
.aykbn .aykbn-dash{left:calc(var(--u)*105);top:calc(var(--u)*81);width:calc(var(--u)*48);height:calc(var(--u)*5);background:#e5112b;border-radius:3px}
.aykbn .aykbn-brand{left:calc(var(--u)*169);top:calc(var(--u)*71);font-weight:700;font-size:calc(var(--u)*21);line-height:calc(var(--u)*28);white-space:nowrap;color:#fff}


/* Headings aur text ko ooper shift kiya gaya hai */
.aykbn .aykbn-h{left:calc(var(--u)*105);top:calc(var(--u)*90);font-family:'Poppins',Arial,sans-serif;font-size:calc(var(--u)*45);line-height:calc(var(--u)*52);font-weight:700;white-space:nowrap;letter-spacing:-.01em;color:#fff;text-transform:none}
.aykbn .aykbn-uline{left:calc(var(--u)*105);top:calc(var(--u)*196);width:calc(var(--u)*765);height:calc(var(--u)*30)}
.aykbn .aykbn-lead{left:calc(var(--u)*105);top:calc(var(--u)*236);font-size:calc(var(--u)*20.5);line-height:calc(var(--u)*30.5);font-weight:400;white-space:nowrap;color:#dbe7fb}
.aykbn .aykbn-feat{left:calc(var(--u)*105);top:calc(var(--u)*353);width:calc(var(--u)*698);list-style:none}

/* .aykbn .aykbn-h{left:calc(var(--u)*105);top:calc(var(--u)*120);font-family:'Poppins',Arial,sans-serif;font-size:calc(var(--u)*45);line-height:calc(var(--u)*52);font-weight:700;white-space:nowrap;letter-spacing:-.01em;color:#fff;text-transform:none} */

.aykbn .aykbn-h .aykbn-hb{color:#ffb703}
/* .aykbn .aykbn-uline{left:calc(var(--u)*105);top:calc(var(--u)*226);width:calc(var(--u)*765);height:calc(var(--u)*30)} */
/* .aykbn .aykbn-lead{left:calc(var(--u)*105);top:calc(var(--u)*266);font-size:calc(var(--u)*20.5);line-height:calc(var(--u)*30.5);font-weight:400;white-space:nowrap;color:#dbe7fb} */
.aykbn .aykbn-lead b{color:#fff;font-weight:600}
/* .aykbn .aykbn-feat{left:calc(var(--u)*105);top:calc(var(--u)*383);width:calc(var(--u)*698);list-style:none} */



.aykbn .aykbn-feat li {
    display: flex;
    align-items: center;
    height: calc(var(--u)*44);
    margin-bottom: calc(var(--u)*12);
    padding-left: calc(var(--u)*15);
    list-style: none;
    border-radius: calc(var(--u)*12); /* Thora kam round for a sharp look */

    /* Premium Dark Glass Look */
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-left: 4px solid #3b82f6; /* Blue accent line */
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    color: #ffffff;
    
    font-size: calc(var(--u)*16);
    font-weight: 500;
    line-height: 1.28;
    white-space: nowrap;
    transition: all 0.3s ease;
}

/* Hover effect: Mouse le jaane par box thora sa right shift hoga */
.aykbn .aykbn-feat li:hover {
    background: rgba(255, 255, 255, 0.1);
    transform: translateX(5px);
}

.aykbn .aykbn-feat li:first-child {
    height: calc(var(--u)*52);
}
/* .aykbn .aykbn-feat li{display:flex;align-items:center;height:calc(var(--u)*44);margin-bottom:calc(var(--u)*10);padding-left:calc(var(--u)*15);list-style:none;
 border-radius:calc(var(--u)*16);

 background:linear-gradient(90deg,rgba(255,255,255,.14),rgba(255,255,255,.05));
  border:1px solid rgba(120,170,255,.28);
  box-shadow:0 calc(var(--u)*4) calc(var(--u)*14) rgba(0,0,0,.35);
  color:#fff;
font-size:calc(var(--u)*17.5);font-weight:400;line-height:1.28;white-space:nowrap;}

.aykbn .aykbn-feat li:first-child{height:calc(var(--u)*52)} */


.aykbn .aykbn-ico {
    flex: none;
    width: calc(var(--u)*66);
    height: calc(var(--u)*46);
    margin-right: calc(var(--u)*17);
    border-radius: calc(var(--u)*10);
    
    /* Naya Lighter Blue Gradient */
    background: linear-gradient(180deg, #52a8ff, #1e7eea);
    display: grid;
    place-items: center;
    
    /* Glow ko bhi thora light kiya hai taake match kare */
    box-shadow: 0 calc(var(--u)*4) calc(var(--u)*8) rgba(30, 126, 234, 0.4);
}



.aykbn .aykbn-ico svg{width:calc(var(--u)*30);height:calc(var(--u)*30);fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* Icons ko ooper shift kiya gaya hai */
.aykbn img.aykbn-badge {
    top: calc(var(--u)*605); 
    width: calc(var(--u)*80);
    height: calc(var(--u)*80);
    max-width: none;
    border-radius: calc(var(--u)*10);
    background: #fff;
    object-fit: contain;
    box-shadow: 0 calc(var(--u)*4) calc(var(--u)*14) rgba(0,0,0,.4);
    transition: all 0.3s ease;
}

/* Icons Hover Effect */
.aykbn img.aykbn-badge:hover {
    transform: translateY(-4px) scale(1.05);
    box-shadow: 0 calc(var(--u)*8) calc(var(--u)*20) rgba(0,0,0,.6);
}
/* .aykbn img.aykbn-badge{top:calc(var(--u)*620);width:calc(var(--u)*105);height:calc(var(--u)*104);max-width:none;border-radius:calc(var(--u)*12);background:#fff;
 object-fit:contain;box-shadow:0 calc(var(--u)*4) calc(var(--u)*14) rgba(0,0,0,.4)} */


 /* Button Normal State */
/* Button Normal State */
.aykbn a.aykbn-cta {
    left: calc(var(--u)*105);
    top: calc(var(--u)*715); /* 700 se barha kar 745 kiya taake logos ke baad aaye */
    width: calc(var(--u)*280);
    height: calc(var(--u)*48);
    border-radius: calc(var(--u)*10);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: calc(var(--u)*10);
    color: #fff;
    text-decoration: none;
    font-weight: 600;
    font-size: calc(var(--u)*18);
    background: linear-gradient(180deg,#f0213a,#c80c26);
    box-shadow: 0 calc(var(--u)*6) calc(var(--u)*16) rgba(200,12,38,.35);
    transition: all 0.3s ease;
}

/* Button Hover & Focus State (Yeh zaroori tha) */
.aykbn a.aykbn-cta:hover,
.aykbn a.aykbn-cta:focus {
    background: linear-gradient(180deg, #ff3352, #a80a1f);
    transform: translateY(-3px);
    box-shadow: 0 calc(var(--u)*10) calc(var(--u)*22) rgba(200,12,38,.6);
}

/* Button Arrow SVG */
.aykbn .aykbn-cta svg {
    width: calc(var(--u)*20); 
    height: calc(var(--u)*20); 
    stroke: #fff; 
    fill: none; 
    stroke-width: 2.4; 
    stroke-linecap: round; 
    stroke-linejoin: round;
    transition: transform 0.3s ease;
}

/* Hover karne par arrow thora aage jayega */
.aykbn a.aykbn-cta:hover svg {
    transform: translateX(4px);
}
/* .aykbn a.aykbn-cta,.aykbn a.aykbn-cta:hover,.aykbn a.aykbn-cta:focus{left:calc(var(--u)*105);top:calc(var(--u)*749);width:calc(var(--u)*355);height:calc(var(--u)*57);border-radius:calc(var(--u)*13);
 display:flex;align-items:center;justify-content:center;gap:calc(var(--u)*14);color:#fff;text-decoration:none;font-weight:700;font-size:calc(var(--u)*21.5);
 background:linear-gradient(180deg,#f0213a,#c80c26);box-shadow:0 calc(var(--u)*6) calc(var(--u)*16) rgba(200,12,38,.35)}
.aykbn .aykbn-cta svg{width:calc(var(--u)*24);height:calc(var(--u)*24);stroke:#fff;fill:none;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round} */

/* collage */
/* .aykbn .aykbn-pn{background:linear-gradient(180deg, #5d9dec, #6a9df5);transform:skewX(-18deg);z-index:1} */

.aykbn .aykbn-pn {
    background: linear-gradient(135deg, #ffb703, #f59e0b);
    transform: skewX(-18deg);
    z-index: 1;
    box-shadow: 0 0 25px rgba(255, 183, 3, 0.4); /* Golden glow */
}


.aykbn .aykbn-ph{width:calc(var(--u)*252);height:calc(var(--u)*238);z-index:2;overflow:hidden;border-radius:calc(var(--u)*32);transform:skewX(-18deg);
 border:calc(var(--u)*7) solid #fff;background:#fff;box-shadow:0 calc(var(--u)*10) calc(var(--u)*28) rgba(0,0,0,.5)}
.aykbn .aykbn-ph img{display:block;width:135%;max-width:none;height:100%;object-fit:cover;margin-left:-17.5%;transform:skewX(18deg);}



/* ===== RESPONSIVE: desktop par wrappers invisible ===== */
.aykbn .aykbn-badges,
.aykbn .aykbn-collage{display:contents}

/* ===== TABLET + MOBILE ===== */
@media (max-width:1100px){

  .aykbn-outer{background-position:70% top}

  .aykbn{
    max-width:820px;
    aspect-ratio:auto;
    display:flex;
    flex-direction:column;
    gap:18px;
    padding:36px clamp(16px,5vw,40px) 44px;
  }

  .aykbn .aykbn-a{position:static}
  .aykbn .aykbn-pn{display:none}

  /* heading */
  .aykbn .aykbn-h{order:1;white-space:normal;font-size:clamp(24px,6.2vw,38px);line-height:1.2}
  .aykbn .aykbn-h br{display:none}
  .aykbn .aykbn-uline{order:2;width:min(100%,420px);height:auto;aspect-ratio:765/30;margin-top:-6px}

  /* paragraph */
  .aykbn .aykbn-lead{order:3;white-space:normal;font-size:clamp(14px,3.8vw,17px);line-height:1.65}
  .aykbn .aykbn-lead br{display:none}

  /* photos */
  .aykbn .aykbn-collage{order:4;display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
  .aykbn .aykbn-ph{width:auto!important;height:auto!important;aspect-ratio:4/3;transform:none;border-width:3px;border-radius:14px;box-shadow:0 6px 16px rgba(0,0,0,.45)}
  .aykbn .aykbn-ph img{width:100%;height:100%;margin-left:0;transform:none}

  /* feature boxes */
  .aykbn .aykbn-feat{order:5;width:100%}
  .aykbn .aykbn-feat li,
  .aykbn .aykbn-feat li:first-child{
    height:auto;min-height:52px;
    padding:8px 12px 8px 10px;margin-bottom:10px;
    white-space:normal;border-radius:12px;
    font-size:clamp(13px,3.5vw,15px);
  }
  .aykbn .aykbn-feat li br{display:none}
  .aykbn .aykbn-feat li:hover{transform:none}
  .aykbn .aykbn-ico{width:46px;height:40px;margin-right:12px;border-radius:9px}
  .aykbn .aykbn-ico svg{width:24px;height:24px}

  /* logos */
  .aykbn .aykbn-badges{order:6;display:flex;flex-wrap:wrap;gap:10px}
  .aykbn img.aykbn-badge{width:64px;height:64px;border-radius:10px}

  /* button */
  .aykbn a.aykbn-cta{order:7;width:100%;max-width:340px;height:50px;font-size:16px;border-radius:10px;gap:10px}
  .aykbn .aykbn-cta svg{width:18px;height:18px}
}

/* ===== PHONES ===== */
@media (max-width:560px){
  .aykbn{padding:28px 16px 36px;gap:16px}
  .aykbn .aykbn-collage{grid-template-columns:repeat(2,1fr)}
  .aykbn img.aykbn-badge{width:56px;height:56px}
  .aykbn a.aykbn-cta{max-width:none}
}
</style>

<div class="aykbn-outer">
<div class="aykbn">

  
  <h3 class="aykbn-a aykbn-h">AYK Global Training Center for<br><span class="aykbn-hb">Skilled Workforce &amp; Trade Testing</span></h3>

  <svg class="aykbn-a aykbn-uline" viewBox="0 0 765 30" fill="#e91348" stroke="none" aria-hidden="true">
     <path d="M0 9 Q140 14 280 8 Q140 6.5 0 9 Z"/>

     <path d="M535 12 Q680 1 760 25 Q685 11 535 12 Z"/>
</svg>

  <p class="aykbn-a aykbn-lead">We provide <b>professional trade testing</b>, skill development and technical<br>training to prepare skilled Pakistani manpower for <b>international job</b><br><b>requirements</b> and global employers.</p>

  <ul class="aykbn-a aykbn-feat">
    <li><span class="aykbn-ico"><svg viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.4"/><path d="M3 19c0-3.3 2.7-5 6-5s6 1.7 6 5M15 14.2c3 0 6 1 6 4.3"/></svg></span><span>We can conduct up to 200 skilled trade tests per day with a<br>smooth and efficient process.</span></li>
    <li><span class="aykbn-ico"><svg viewBox="0 0 24 24"><path d="M2 9l10-5 10 5-10 5z"/><path d="M6 11.5V16c3 2.5 9 2.5 12 0v-4.5M22 9v6"/></svg></span>State-of-the-Art Technical Training &amp; Skill Development Facilities</li>
    <li><span class="aykbn-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="9" r="6"/><path d="M9 14l-2 7 5-3 5 3-2-7"/></svg></span>Trade Testing &amp; Skill Certification for Skilled Workforce</li>
    <li><span class="aykbn-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg></span>Pakistan &amp; International Deployment-Ready Skilled Workforce</li>
  </ul>

  <!-- Government / certification logos -->
     <!-- Government / certification logos -->

     <div class="aykbn-badges">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*105)" src="img/g-logos/ISO%20Logo.webp" alt="ISO certified" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*200)" src="img/g-logos/POEPA%20Logo.webp" alt="POEPA member" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*295)" src="img/g-logos/ICCI%20Logo.webp" alt="Government certified HR agency in Pakistan" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*390)" src="img/g-logos/UO%20%26%20HRD%20Logo.png" alt="Overseas Pakistanis &amp; HRD" loading="lazy">
  </div>
  <!-- <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*106)" src="img/g-logos/ISO%20Logo.webp" alt="ISO certified" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*227)" src="img/g-logos/POEPA%20Logo.webp" alt="POEPA member" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*348)" src="img/g-logos/ICCI%20Logo.webp" alt="Government certified HR agency in Pakistan" loading="lazy">
  <img class="aykbn-a aykbn-badge" style="left:calc(var(--u)*469)" src="img/g-logos/UO%20%26%20HRD%20Logo.png" alt="Overseas Pakistanis &amp; HRD" loading="lazy"> -->

  <a class="aykbn-a aykbn-cta" href="training.php">Explore Training Center
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h16M14 6l6 6-6 6"/></svg></a>

  <!-- blue accent panels behind photos -->
  <div class="aykbn-a aykbn-pn" style="left:calc(var(--u)*1010);top:calc(var(--u)*173);width:calc(var(--u)*156);height:calc(var(--u)*60);border-radius:calc(var(--u)*16) calc(var(--u)*16) 0 0"></div>
  <div class="aykbn-a aykbn-pn" style="left:calc(var(--u)*1650);top:calc(var(--u)*310);width:calc(var(--u)*72);height:calc(var(--u)*172);border-radius:calc(var(--u)*30)"></div>
  <div class="aykbn-a aykbn-pn" style="left:calc(var(--u)*830);top:calc(var(--u)*525);width:calc(var(--u)*185);height:calc(var(--u)*195);border-radius:calc(var(--u)*30)"></div>


  <div class="aykbn-collage">
  <!-- photos (row 1) -->
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*906);top:calc(var(--u)*203)"><img src="img/trraining-construction.jpeg" alt="Best training center in Pakistan" loading="lazy"></div>
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*1185);top:calc(var(--u)*203)"><img src="img/electrician-training.jpg" alt="AYK Global training center" loading="lazy"></div>
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*1463);top:calc(var(--u)*203)"><img src="img/plumber-training.jpg" alt="Plumber training center" loading="lazy"></div>
  <!-- photos (row 2) -->
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*864);top:calc(var(--u)*462);height:calc(var(--u)*234)"><img src="img/pipefitter-trainig.jpeg" alt="Pipefitter training provider" loading="lazy"></div>
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*1136);top:calc(var(--u)*462);height:calc(var(--u)*234)"><img src="img/welder-trainig.jpeg" alt="Certified welder training provider" loading="lazy"></div>
  <div class="aykbn-a aykbn-ph" style="left:calc(var(--u)*1407);top:calc(var(--u)*462);height:calc(var(--u)*234)"><img src="img/carpenter-training.jpeg" alt="Carpenter training center" loading="lazy"></div>

</div>

</div>
</div>
<!-- ===================== /AYK TRAINING BANNER ===================== -->




<?php
/*
|--------------------------------------------------------------------------
| AYK GLOBAL - DYNAMIC REVIEWS
|--------------------------------------------------------------------------
| Replace your COMPLETE hard-coded:
|
| <section class="testi-sec">
|     ...
| </section>
|
| with this section.
|
| Existing DB:
| /home/j8j5y4cejw2s/public_html/forms/db.php
|--------------------------------------------------------------------------
*/


/*
|--------------------------------------------------------------------------
| Load existing database connection
|--------------------------------------------------------------------------
*/

require_once 'forms/db.php';


/*
|--------------------------------------------------------------------------
| Detect existing database connection
|--------------------------------------------------------------------------
|
| This avoids assuming that your db.php uses $pdo.
|
*/

$reviewDB = null;
$reviewDBType = null;


/*
|--------------------------------------------------------------------------
| PDO connection
|--------------------------------------------------------------------------
*/

if (isset($pdo) && $pdo instanceof PDO) {

    $reviewDB = $pdo;
    $reviewDBType = 'pdo';

}


/*
|--------------------------------------------------------------------------
| MySQLi connection: $conn
|--------------------------------------------------------------------------
*/

elseif (
    isset($conn) &&
    $conn instanceof mysqli
) {

    $reviewDB = $conn;
    $reviewDBType = 'mysqli';

}


/*
|--------------------------------------------------------------------------
| MySQLi connection: $mysqli
|--------------------------------------------------------------------------
*/

elseif (
    isset($mysqli) &&
    $mysqli instanceof mysqli
) {

    $reviewDB = $mysqli;
    $reviewDBType = 'mysqli';

}


/*
|--------------------------------------------------------------------------
| If no connection was found
|--------------------------------------------------------------------------
*/

if (!$reviewDB) {

    /*
     * Do not break the entire homepage if the review database
     * connection is unavailable.
     */

    $reviews = [];

} else {


    /*
    |--------------------------------------------------------------------------
    | Get active reviews
    |--------------------------------------------------------------------------
    */

    if ($reviewDBType === 'pdo') {

        $reviewStmt = $reviewDB->prepare("
            SELECT
                id,
                reviewer_name,
                review_text,
                avatar,
                rating,
                review_age,
                source
            FROM reviews
            WHERE is_active = 1
            ORDER BY sort_order ASC, id ASC
        ");

        $reviewStmt->execute();

        $reviews = $reviewStmt->fetchAll(PDO::FETCH_ASSOC);

    }


    elseif ($reviewDBType === 'mysqli') {

        $reviewResult = $reviewDB->query("
            SELECT
                id,
                reviewer_name,
                review_text,
                avatar,
                rating,
                review_age,
                source
            FROM reviews
            WHERE is_active = 1
            ORDER BY sort_order ASC, id ASC
        ");

        $reviews = [];

        if ($reviewResult) {

            while ($row = $reviewResult->fetch_assoc()) {

                $reviews[] = $row;

            }

            $reviewResult->free();

        }

    }

}


/*
|--------------------------------------------------------------------------
| Escape helper
|--------------------------------------------------------------------------
*/

if (!function_exists('ayk_review_escape')) {

    function ayk_review_escape($value)
    {
        return htmlspecialchars(
            (string)$value,
            ENT_QUOTES,
            'UTF-8'
        );
    }

}

?>

<style>
/* =========================================================
   AYK GLOBAL PREMIUM REVIEW SECTION
   Isolated styling, independent from existing testimonial CSS
   ========================================================= */

.testi-sec {
    width: 100% !important;
    max-width: 100% !important;
    padding: 75px 0 85px !important;
    margin: 0 !important;
    overflow: hidden !important;
    background: #f7f9fc !important;
    box-sizing: border-box !important;
}

.testi-sec *,
.testi-sec *::before,
.testi-sec *::after {
    box-sizing: border-box !important;
}


/* ---------------------------------------------------------
   HEADING
   --------------------------------------------------------- */

.testi-sec .testi-heading {
    width: 100% !important;
    max-width: 760px !important;

    margin: 0 auto 38px !important;
    padding: 0 20px !important;

    text-align: center !important;

    font-family: inherit !important;
    font-size: 30px !important;
    line-height: 1.35 !important;
    font-weight: 700 !important;

    color: #0b2a4a !important;
}


/* ---------------------------------------------------------
   SLIDER VIEWPORT
   --------------------------------------------------------- */

.testi-sec .testi-slider {
    width: 100% !important;
    max-width: 1200px !important;

    margin: 0 auto !important;

    overflow: hidden !important;

    position: relative !important;
}


/* ---------------------------------------------------------
   TRACK
   --------------------------------------------------------- */

.testi-sec .testi-track {
    display: flex !important;

    align-items: stretch !important;

    gap: 22px !important;

    width: max-content !important;

    padding: 15px 10px 25px !important;
    margin: 0 !important;

    animation: aykReviewScroll 65s linear infinite !important;

    will-change: transform !important;
}



.process {
    padding: 40px 20px;
    background-color: #f4f8fc;
    text-align: center;
}

.process-title {
    font-size: 28px;
    font-weight: 700;
    color: #0d3b66;
    margin-bottom: 40px;
}

.process-steps {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    position: relative;
    max-width: 1200px;
    margin: 0 auto;
    flex-wrap: wrap; /* Mobile screen par wrap hone ke liye */
}

/* Background Connecting Line */
.process-steps::before {
    content: '';
    position: absolute;
    top: 30px;
    left: 5%;
    right: 5%;
    height: 2px;
    background-color: #d1d5db;
    z-index: 1;
}

.step {
    flex: 1 1 11%; /* All 8 items fits nicely on desktop */
    min-width: 150px;
    position: relative;
    z-index: 2;
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 20px;
}

.circle {
    width: 45px;
    height: 45px;
    background-color: #ffffff;
    border: 2px solid #e63946;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    color: #e63946;
    font-size: 20px;
    margin-bottom: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}



/* ==========================================================================
   FINAL FIXED CSS - POPPINS FONT + WORKING FONT AWESOME ICONS
   ========================================================================== */
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800&display=swap');

:root {
  --ayk-blue: #1d63b8;            /* Primary accent blue */
  --ayk-text-heading: #0f172a;    /* Main title color */
  --ayk-text-label: #8c9bb0;      /* Muted label color */
  --ayk-text-address: #718096;    /* Address text color */
  --ayk-red-notice: #c84242;      /* Red notice text */
  --ayk-bg-card: #ffffff;
  --ayk-border-light: #edf2f7;
  --ayk-icon-bg: #eff6ff;
  --ayk-font-family: 'Poppins', system-ui, -apple-system, sans-serif;
}

/* Base Body Font */
body {
  font-family: var(--ayk-font-family);
  background-color: #f7fafc;
  margin: 0;
  padding: 0;
  color: var(--ayk-text-heading);
}

/* Ensure Text Elements Use Poppins */
h1, h2, h3, h4, h5, h6, p, span, a, small, div, button {
  font-family: var(--ayk-font-family);
}

/* FIX: Prevent Poppins Override on Font Awesome Icons */
.fa, .fas, .far, .fal, .fad, .fab, 
i[class*="fa-"], span[class*="fa-"] {
  font-family: "Font Awesome 6 Free", "Font Awesome 5 Free", "FontAwesome" !important;
}

/* ==========================================================================
   SECTION CONTAINER & MAIN TOP HEADING
   ========================================================================== */
.ayk-contact-offices {
  max-width: 1140px;
  margin: 0 auto;
  padding: 60px 20px;
}

.ayk-contact-offices-heading {
  text-align: center;
  margin-bottom: 45px;
}

.ayk-contact-offices-heading .ayk-contact-kicker {
  font-size: 12px;
  font-weight: 700;
  color: var(--ayk-blue);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  margin-bottom: 8px;
  display: block;
}

.ayk-contact-offices-heading h2 {
  font-size: 32px !important;
  font-weight: 700 !important;
  color: var(--ayk-text-heading);
  margin: 0 0 12px 0;
  letter-spacing: -0.5px;
}

.ayk-contact-offices-heading p {
  font-size: 15px !important;
  color: #64748b !important;
  max-width: 680px;
  margin: 0 auto;
  line-height: 1.6;
}

/* Offices Cards Grid */
.ayk-offices-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 32px;
  margin-bottom: 50px;
}

/* ==========================================================================
   OFFICE CARDS STYLING (ISLAMABAD & KARACHI)
   ========================================================================== */
.ayk-office-card-v2 {
  background: var(--ayk-bg-card);
  border-radius: 20px;
  overflow: hidden;
  box-shadow: 0 6px 25px rgba(0, 0, 0, 0.03);
  border: 1px solid var(--ayk-border-light);
  display: flex;
  flex-direction: column;
  height: 100%;
}

.ayk-office-image-v2 {
  position: relative;
  height: 190px;
  width: 100%;
}

.ayk-office-image-v2 img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.ayk-office-city-v2 {
  position: absolute;
  bottom: 16px;
  left: 16px;
  background-color: #ffffff;
  color: #0f172a;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  padding: 6px 16px;
  border-radius: 50px;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.12);
}

.ayk-office-body-v2 {
  padding: 28px 30px 24px 30px;
  display: flex;
  flex-direction: column;
  flex-grow: 1;
}

.ayk-office-location-label-v2 {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 700;
  color: var(--ayk-blue);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 4px;
}

.ayk-office-body-v2 h3 {
  font-size: 24px;
  font-weight: 700;
  color: var(--ayk-text-heading);
  margin: 0 0 24px 0;
  letter-spacing: -0.3px;
}

.ayk-office-contact-v2 {
  display: flex;
  flex-direction: column;
  gap: 20px;
  margin-bottom: 26px;
}

.ayk-office-contact-item-v2 {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  text-decoration: none;
  color: var(--ayk-text-heading);
}

.ayk-office-icon-v2 {
  width: 32px;
  height: 32px;
  min-width: 32px;
  border-radius: 50%;
  background-color: var(--ayk-icon-bg);
  color: var(--ayk-blue);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  margin-top: 1px;
}

.ayk-office-contact-item-v2 > span:not(.ayk-office-icon-v2) {
  display: flex;
  flex-direction: column;
  font-size: 14px;
  font-weight: 600;
  color: var(--ayk-text-heading);
  line-height: 1.35;
}

.ayk-office-contact-item-v2 small {
  font-size: 10px !important;
  font-weight: 600 !important;
  color: var(--ayk-text-label) !important;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  margin-bottom: 3px;
  display: block;
}

.ayk-inline-notice-v2 {
  font-size: 11px;
  font-weight: 500;
  color: var(--ayk-red-notice);
  margin-top: 2px;
  display: block;
}

.ayk-office-address-v2 {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding-top: 20px;
  border-top: 1px dashed #e2e8f0;
  margin-bottom: 22px;   /* ✅ Space below address (gap fix) */
  /* margin-top: auto;  ❌ REMOVED — was causing extra space in Islamabad card */
}

.ayk-office-address-v2 i {
  color: var(--ayk-blue);
  font-size: 14px;
  margin-top: 2px;
  flex-shrink: 0;        /* ✅ Icon squeeze na ho */
}

.ayk-office-address-v2 p {
  font-size: 13px;
  color: var(--ayk-text-address) !important;
  margin: 0;
  line-height: 1.5;
  font-weight: 400;
}

.ayk-office-action-v2 {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: transparent !important;
  border: none !important;
  padding: 4px 0 0 0 !important;
  color: var(--ayk-blue);
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;

  margin-top: auto;      /* ✅ Button pushed to bottom instead of address */
}

.ayk-office-action-v2:hover {
  text-decoration: underline;
}

/* ==========================================================================
   MAP CARD SECTION (ALL HEADING TEXT 100% CENTER-ALIGNED)
   ========================================================================== */
.ayk-contact-map-card {
  background: var(--ayk-bg-card);
  border-radius: 20px;
  padding: 32px;
  box-shadow: 0 6px 25px rgba(0, 0, 0, 0.03);
  border: 1px solid var(--ayk-border-light);
  position: relative;
}

/* Centered Header Block */
.ayk-contact-map-heading {
  text-align: center !important;
  margin-bottom: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  width: 100%;
}

.ayk-contact-map-heading .ayk-contact-kicker {
  font-size: 11px;
  font-weight: 700;
  color: var(--ayk-blue);
  letter-spacing: 1.2px;
  text-transform: uppercase;
  margin-bottom: 6px;
  display: block;
  text-align: center !important;
}

.ayk-contact-map-heading h3 {
  font-size: 24px;
  font-weight: 700;
  color: var(--ayk-text-heading);
  margin: 0 0 8px 0;
  letter-spacing: -0.3px;
  text-align: center !important;
}

.ayk-contact-map-heading p {
  font-size: 14px;
  color: var(--ayk-text-address);
  margin: 0;
  line-height: 1.4;
  text-align: center !important;
}

/* Absolute Right Top Link Button */
.ayk-contact-map-link {
  position: absolute;
  top: 32px;
  right: 32px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background-color: #ffffff;
  color: var(--ayk-blue);
  border: 1px solid #e2e8f0;
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 600;
  text-decoration: none;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
  white-space: nowrap;
  transition: all 0.2s ease;
}

.ayk-contact-map-link:hover {
  background-color: var(--ayk-blue);
  color: #ffffff;
  border-color: var(--ayk-blue);
}

/* Map Frame Box */
.ayk-contact-map {
  width: 100%;
  height: 420px;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid #e2e8f0;
}

.ayk-contact-map iframe {
  width: 100%;
  height: 100%;
  border: 0;
}

/* ==========================================================================
   RESPONSIVE BREAKPOINTS
   ========================================================================== */
@media (max-width: 992px) {
  .ayk-contact-map-card {
    display: flex;
    flex-direction: column;
  }

  .ayk-contact-map-link {
    position: static;
    margin-top: 14px;
    align-self: center;
  }
}

@media (max-width: 768px) {
  .ayk-offices-grid {
    grid-template-columns: 1fr;
    gap: 24px;
  }

  .ayk-contact-offices {
    padding: 30px 16px;
  }

  .ayk-office-body-v2,
  .ayk-contact-map-card {
    padding: 20px;
  }

  .ayk-contact-map {
    height: 320px;
  }
}







/* ---------------------------------------------------------
   PROCESS STEPS — CLEAN SINGLE ROW
--------------------------------------------------------- */

.process-steps {
    display: grid !important;
    grid-template-columns: repeat(8, minmax(0, 1fr)) !important;
    align-items: start !important;
    position: relative;
    max-width: 1250px;
    width: 100%;
    margin: 0 auto;
    gap: 8px !important;
}

/* Connecting Line */
.process-steps::before {
    content: '';
    position: absolute;
    top: 22px;
    left: 5%;
    right: 5%;
    height: 2px;
    background-color: #d1d5db;
    z-index: 1;
}


/* ---------------------------------------------------------
   EACH STEP
--------------------------------------------------------- */

.step {
    width: 100% !important;
    min-width: 0 !important;

    position: relative;
    z-index: 2;

    display: flex !important;
    flex-direction: column !important;
    align-items: center !important;

    text-align: center !important;
    margin: 0 !important;
    padding: 0 3px !important;
}


/* ---------------------------------------------------------
   ICON CIRCLE
--------------------------------------------------------- */

.circle {
    width: 45px;
    height: 45px;

    flex: 0 0 45px;

    background-color: #ffffff;
    border: 2px solid #e63946;
    border-radius: 50%;

    display: flex;
    justify-content: center;
    align-items: center;

    color: #e63946;
    font-size: 20px;

    margin: 0 auto 14px;

    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
}


/* ---------------------------------------------------------
   STEP TEXT
--------------------------------------------------------- */

.step p,
.step span,
.step-title {
    width: 150% !important;

    font-size: 10.3px !important;
    line-height: 1.35 !important;

    color: #111827;

    text-align: center !important;

    margin: 0 !important;
    padding: 0 !important;

    white-space: normal !important;
    word-break: normal !important;
    overflow-wrap: normal !important;

    /* Same text area height for every item */
    min-height: 38px !important;
}





/* Mobile Screens Styling */
@media (max-width: 768px) {
    .process-steps::before {
        display: none; /* Hide horizontal line on mobile */
    }
    .step {
        flex: 1 1 45%; /* 2 items per row on mobile */
    }
}



/* ---------------------------------------------------------
   REVIEW CARD
   --------------------------------------------------------- */

.testi-sec .testi-card {

    position: relative !important;

    flex: 0 0 350px !important;

    width: 350px !important;
    min-width: 350px !important;
    max-width: 350px !important;

    height: 255px !important;
    min-height: 255px !important;
    max-height: 255px !important;

    display: flex !important;
    flex-direction: column !important;

    padding: 22px !important;

    margin: 0 !important;

    background: #ffffff !important;

    border: 1px solid #e9edf3 !important;

    border-radius: 18px !important;

    box-shadow:
        0 8px 25px rgba(15, 35, 65, 0.07) !important;

    overflow: hidden !important;

    transform: translateZ(0);

    transition:
        transform .3s ease,
        box-shadow .3s ease,
        border-color .3s ease !important;
}


/* ---------------------------------------------------------
   CARD HOVER
   --------------------------------------------------------- */

.testi-sec .testi-card:hover {
    transform: translateY(-6px) !important;

    border-color: #dce6f3 !important;

    box-shadow:
        0 18px 40px rgba(15, 35, 65, 0.12) !important;
}


/* ---------------------------------------------------------
   TOP PROFILE AREA
   --------------------------------------------------------- */

.testi-sec .testi-top {

    width: 100% !important;

    min-height: 48px !important;

    display: flex !important;

    align-items: center !important;

    gap: 11px !important;

    position: relative !important;

    padding: 0 30px 0 0 !important;

    margin: 0 !important;

    flex-shrink: 0 !important;
}


/* ---------------------------------------------------------
   AVATAR
   --------------------------------------------------------- */

.testi-sec .user-img {

    width: 46px !important;
    height: 46px !important;

    min-width: 46px !important;
    max-width: 46px !important;

    min-height: 46px !important;
    max-height: 46px !important;

    flex: 0 0 46px !important;

    display: block !important;

    border-radius: 50% !important;

    object-fit: cover !important;

    background: #eef3f8 !important;

    border: 2px solid #ffffff !important;

    box-shadow:
        0 3px 10px rgba(0,0,0,.10) !important;
}


/* ---------------------------------------------------------
   FALLBACK AVATAR
   --------------------------------------------------------- */

.testi-sec .review-avatar-fallback {

    display: flex !important;

    align-items: center !important;
    justify-content: center !important;

    background:
        linear-gradient(
            135deg,
            #1769e0,
            #e83d86
        ) !important;

    color: #ffffff !important;

    font-size: 16px !important;

    font-weight: 700 !important;
}


/* ---------------------------------------------------------
   REVIEWER DETAILS
   --------------------------------------------------------- */

.testi-sec .reviewer-info {

    min-width: 0 !important;

    flex: 1 !important;

    display: flex !important;

    flex-direction: column !important;

    justify-content: center !important;

    overflow: hidden !important;
}


.testi-sec .reviewer-name {

    display: block !important;

    width: 100% !important;

    margin: 0 !important;
    padding: 0 !important;

    color: #172033 !important;

    font-size: 14px !important;

    line-height: 1.25 !important;

    font-weight: 700 !important;

    white-space: nowrap !important;

    overflow: hidden !important;

    text-overflow: ellipsis !important;
}


.testi-sec .review-age {

    display: block !important;

    margin: 4px 0 0 !important;

    color: #8993a4 !important;

    font-size: 11px !important;

    line-height: 1.2 !important;
}


/* ---------------------------------------------------------
   GOOGLE ICON
   --------------------------------------------------------- */

.testi-sec .google-icon {

    position: absolute !important;

    top: 2px !important;
    right: 0 !important;

    width: 21px !important;
    height: 21px !important;

    min-width: 21px !important;
    max-width: 21px !important;

    object-fit: contain !important;

    margin: 0 !important;
}


/* ---------------------------------------------------------
   RATING
   --------------------------------------------------------- */

.testi-sec .stars {

    display: block !important;

    width: 100% !important;

    margin: 15px 0 11px !important;
    padding: 0 !important;

    color: #f7b900 !important;

    font-size: 16px !important;

    line-height: 1 !important;

    letter-spacing: 1px !important;

    flex-shrink: 0 !important;
}


/* ---------------------------------------------------------
   REVIEW TEXT
   --------------------------------------------------------- */

.testi-sec .review-text {

    position: relative !important;

    width: 100% !important;

    flex: 1 1 auto !important;

    min-height: 0 !important;

    margin: 0 !important;
    padding: 0 2px 0 0 !important;

    color: #596579 !important;

    font-size: 13.5px !important;

    line-height: 1.6 !important;

    font-weight: 400 !important;

    overflow: hidden !important;

    word-break: normal !important;

    overflow-wrap: break-word !important;

    white-space: normal !important;

    display: -webkit-box !important;

    -webkit-box-orient: vertical !important;

    -webkit-line-clamp: 7 !important;
}


/* ---------------------------------------------------------
   QUOTE DECORATION
   --------------------------------------------------------- */

.testi-sec .testi-card::after {

    content: "”";

    position: absolute;

    right: 15px;
    bottom: -17px;

    font-family: Georgia, serif;

    font-size: 85px;

    line-height: 1;

    color: rgba(23, 105, 224, .045);

    pointer-events: none;
}


/* ---------------------------------------------------------
   EMPTY STATE
   --------------------------------------------------------- */

.testi-sec .testi-empty {

    width: 350px;

    padding: 30px;

    text-align: center;

    color: #777;

    background: #ffffff;

    border-radius: 18px;
}


/* ---------------------------------------------------------
   ANIMATION
   --------------------------------------------------------- */

@keyframes aykReviewScroll {

    0% {
        transform: translate3d(0, 0, 0);
    }

    100% {
        transform: translate3d(-50%, 0, 0);
    }

}


/* ---------------------------------------------------------
   PAUSE
   --------------------------------------------------------- */

.testi-sec .testi-slider:hover .testi-track {
    animation-play-state: paused !important;
}


/* =========================================================
   TABLET
   ========================================================= */

@media (max-width: 1100px) {

    .testi-sec .testi-slider {
        max-width: 900px !important;
    }

    .testi-sec .testi-card {

        flex-basis: 320px !important;

        width: 320px !important;
        min-width: 320px !important;
        max-width: 320px !important;

        height: 245px !important;
        min-height: 245px !important;
        max-height: 245px !important;
    }

}


/* =========================================================
   MOBILE
   ========================================================= */

@media (max-width: 768px) {

    .testi-sec {

        padding: 55px 0 65px !important;
    }


    .testi-sec .testi-heading {

        max-width: 600px !important;

        margin-bottom: 28px !important;

        padding: 0 18px !important;

        font-size: 23px !important;

        line-height: 1.4 !important;
    }


    .testi-sec .testi-slider {

        width: 100% !important;

        max-width: 100% !important;
    }


    .testi-sec .testi-track {

        gap: 15px !important;

        padding: 12px 15px 22px !important;

        animation-duration: 85s !important;
    }


    .testi-sec .testi-card {

        flex: 0 0 285px !important;

        width: 285px !important;
        min-width: 285px !important;
        max-width: 285px !important;

        height: 230px !important;
        min-height: 230px !important;
        max-height: 230px !important;

        padding: 18px !important;

        border-radius: 16px !important;
    }


    .testi-sec .user-img {

        width: 43px !important;
        height: 43px !important;

        min-width: 43px !important;
        max-width: 43px !important;

        min-height: 43px !important;
        max-height: 43px !important;

        flex-basis: 43px !important;
    }


    .testi-sec .reviewer-name {

        font-size: 13px !important;
    }


    .testi-sec .stars {

        margin: 13px 0 9px !important;

        font-size: 15px !important;
    }


    .testi-sec .review-text {

        font-size: 12.8px !important;

        line-height: 1.55 !important;

        -webkit-line-clamp: 7 !important;
    }

}


/* =========================================================
   SMALL MOBILE
   ========================================================= */

@media (max-width: 480px) {

    .testi-sec {

        padding: 48px 0 55px !important;
    }


    .testi-sec .testi-heading {

        font-size: 21px !important;

        padding: 0 15px !important;

        margin-bottom: 23px !important;
    }


    .testi-sec .testi-track {

        gap: 13px !important;

        padding-left: 13px !important;
        padding-right: 13px !important;

        animation-duration: 95s !important;
    }


    .testi-sec .testi-card {

        flex: 0 0 270px !important;

        width: 270px !important;
        min-width: 270px !important;
        max-width: 270px !important;

        height: 225px !important;
        min-height: 225px !important;
        max-height: 225px !important;

        padding: 17px !important;
    }


    .testi-sec .review-text {

        font-size: 12.5px !important;

        line-height: 1.5 !important;
    }

}
</style>


<section class="testi-sec">

    <h3 class="testi-heading">
        Trusted by Candidates for Connecting Them With the Right International Opportunities
    </h3>


    <div class="testi-slider">

        <div class="testi-track">


            <?php if (!empty($reviews)): ?>


                <?php foreach ($reviews as $review): ?>

                    <article class="testi-card">


                        
                        <div class="testi-top">


                            <?php if (!empty($review['avatar'])): ?>

                                <img
                                    src="<?= ayk_review_escape($review['avatar']) ?>"
                                    class="user-img"
                                    alt="<?= ayk_review_escape($review['reviewer_name']) ?> review"
                                    loading="lazy"
                                    decoding="async"
                                    width="46"
                                    height="46"
                                >

                            <?php else: ?>

                                <div class="user-img review-avatar-fallback">

                                    <?= ayk_review_escape(
                                        strtoupper(
                                            substr(
                                                trim($review['reviewer_name']),
                                                0,
                                                1
                                            )
                                        )
                                    ) ?>

                                </div>

                            <?php endif; ?>


                            <div class="reviewer-info">

                                <p class="reviewer-name">
                                    <?= ayk_review_escape(
                                        $review['reviewer_name']
                                    ) ?>
                                </p>


                                <small class="review-age">
                                    <?= ayk_review_escape(
                                        $review['review_age']
                                    ) ?>
                                </small>

                            </div>


                            <?php if (
                                strtolower(
                                    trim(
                                        (string)$review['source']
                                    )
                                ) === 'google'
                            ): ?>

                                <img
                                    src="img/google.webp"
                                    class="google-icon"
                                    alt="Google review"
                                    loading="lazy"
                                    decoding="async"
                                    width="21"
                                    height="21"
                                >

                            <?php endif; ?>


                        </div>


                        
                        <div
                            class="stars"
                            aria-label="<?= (int)$review['rating'] ?> out of 5 stars"
                        >

                            <?= str_repeat(
                                '★',
                                max(
                                    1,
                                    min(
                                        5,
                                        (int)$review['rating']
                                    )
                                )
                            ) ?>

                        </div>


                        
                        <div class="review-text">

                            <?= nl2br(
                                ayk_review_escape(
                                    $review['review_text']
                                )
                            ) ?>

                        </div>


                    </article>

                <?php endforeach; ?>


            <?php else: ?>


                <div class="testi-empty">
                    No reviews available at the moment.
                </div>


            <?php endif; ?>


        </div>

    </div>

</section>

<?php

require_once $_SERVER['DOCUMENT_ROOT'] . '/blog/includes/db.php';

$recentBlogs = [];

// Fetch posts created 3 days ago and older (excluding today and the last 2 days)
$stmt = $conn->prepare("
    SELECT
        id,
        title,
        slug,
        image,
        created_at
    FROM blogs
    WHERE created_at <= DATE_SUB(CURDATE(), INTERVAL 3 DAY)
    ORDER BY created_at DESC
    LIMIT 3
");

if ($stmt) {
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $recentBlogs[] = $row;
    }

    $stmt->close();
}

?>



<section class="news-sec">

    <div class="news-container">

        <h3 class="mb-4" style="font-size: 32px; font-weight: 600;">
            Recent News &amp; Updates
        </h3>

        <?php if (!empty($recentBlogs)): ?>

            <div class="news-grid">

                <?php foreach ($recentBlogs as $blog): ?>

                    <?php
                    $blogTitle = $blog['title'] ?? '';
                    $blogSlug  = $blog['slug'] ?? '';
                    $blogImage = $blog['image'] ?? '';

                    /*
                     * If your database stores:
                     * blogs/image.webp
                     * then this will use it directly.
                     *
                     * If it stores only:
                     * image.webp
                     * then it will use /img/blogs/
                     */
                    if ($blogImage !== '') {

                        if (
                            str_starts_with($blogImage, '/') ||
                            str_starts_with($blogImage, 'http://') ||
                            str_starts_with($blogImage, 'https://')
                        ) {
                            $imageUrl = $blogImage;
                        } else {
                            $imageUrl = '/blog/uploads/' . ltrim($blogImage, '/');
                        }

                    } else {
                        $imageUrl = '/img/blogs/default.webp';
                    }

                    /*
                     * Blog URL
                     * Change this if your actual blog URL structure
                     * is different.
                     */
                    $blogUrl = '/blog/' . rawurlencode($blogSlug);

                    /*
                     * Format database timestamp
                     * Example: April 15, 2026
                     */
                    $blogDate = !empty($blog['created_at'])
                        ? date('F j, Y', strtotime($blog['created_at']))
                        : '';
                    ?>

                    <article class="news-card">

                        <a
                            href="<?= htmlspecialchars($blogUrl, ENT_QUOTES, 'UTF-8') ?>"
                            aria-label="<?= htmlspecialchars($blogTitle, ENT_QUOTES, 'UTF-8') ?>"
                        >

                            <img
                                src="<?= htmlspecialchars($imageUrl, ENT_QUOTES, 'UTF-8') ?>"
                                alt="<?= htmlspecialchars($blogTitle, ENT_QUOTES, 'UTF-8') ?>"
                                loading="lazy"
                                decoding="async"
                                fetchpriority="low"
                            >

                        </a>

                        <div class="news-content">

                            <a
                                href="<?= htmlspecialchars($blogUrl, ENT_QUOTES, 'UTF-8') ?>"
                            >
                                <h3>
                                    <?= htmlspecialchars($blogTitle, ENT_QUOTES, 'UTF-8') ?>
                                </h3>
                            </a>

                            <?php if ($blogDate): ?>

                                <span>
                                    <?= htmlspecialchars($blogDate, ENT_QUOTES, 'UTF-8') ?>
                                </span>

                            <?php endif; ?>

                        </div>

                    </article>

                <?php endforeach; ?>

            </div>

        <?php else: ?>

            <div class="news-empty p-4" >
                <p>No recent news available.</p>
            </div>

        <?php endif; ?>

    </div>

</section>      







<section class="ayk-contact-offices">
    <div class="container">

        <div class="ayk-contact-offices-heading text-center">
            <span class="ayk-contact-kicker">OUR LOCATIONS</span>
            <h2 style="font-size: 32px; font-weight: 600;">Explore Our Offices</h2>

            <p style="font-size: 16px; color: #000000;">
                Looking to hire new talent or explore recruitment solutions?
                Visit one of our offices or connect with our team today to get started.
            </p>
        </div>

        <div class="row g-4 justify-content-center">

            <!-- Islamabad Office Card -->
            <div class="col-12 col-md-6 col-xl-4">
                <div class="ayk-office-card-v2">

                    <div class="ayk-office-image-v2">
                        <img src="img/faisal-mosque.jpeg"
                             alt="AYK Overseas Islamabad Office"
                             loading="lazy">

                        <span class="ayk-office-city-v2">
                            Islamabad
                        </span>
                    </div>

                    <div class="ayk-office-body-v2">

                        <div class="ayk-office-location-label-v2">
                            <i class="fas fa-location-dot"></i>
                            Islamabad Office
                        </div>

                        <h3>Islamabad</h3>

                        <!--<div class="ayk-office-contact-v2">-->

                        <!--    <a href="tel:02134392918"-->
                        <!--       class="ayk-employer-wa-trigger ayk-office-contact-item-v2"-->
                        <!--       role="button"-->
                        <!--       aria-haspopup="dialog"-->
                        <!--       aria-controls="aykEmployerWaModal">-->

                        <!--        <span class="ayk-office-icon-v2">-->
                        <!--            <i class="fab fa-whatsapp"></i>-->
                        <!--        </span>-->

                        <!--        <span>-->
                        <!--            <small style="color: #000000;">-->
                        <!--                Employer Line-->
                        <!--            </small>-->

                        <!--           02134392918-->

                        <!--            <span class="ayk-inline-notice-v2">-->
                        <!--                (For Companies & Employers Only)-->
                        <!--            </span>-->
                        <!--        </span>-->

                        <!--    </a>-->
                        
                        
                        
                        
                        
                        
                        
                        
                         <div class="ayk-office-contact-v2">

                            <a href="tel:02134392918"
                               class="ayk-office-contact-item-v2"
                               role="button"
                               aria-haspopup="dialog"
                               aria-controls="aykEmployerWaModal">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Employer Line
                                    </small>

                                   02134392918

                                    <span class="ayk-inline-notice-v2">
                                        (For Companies & Employers Only)
                                    </span>
                                </span>

                            </a>

                        
                        
                        

                            <a href="tel:02134392918"
                               class="ayk-office-contact-item-v2">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Job Applicant Mobile Line
                                    </small>

                                    02134392918

                                    <span class="ayk-inline-notice-v2">
                                        (For Job Applications)
                                    </span>
                                </span>

                            </a>

                            <a href="tel:0512769919"
                               class="ayk-office-contact-item-v2">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Landline
                                    </small>

                                    051 2769919
                                </span>

                            </a>

                        </div>

                        <div class="ayk-office-address-v2">

                            <i class="fas fa-location-dot"></i>

                            <p style="color: #000000;">
                                Office No 04, 3rd Floor, Capitol Plaza,
                                G11 Markaz, Islamabad.
                            </p>

                        </div>

                        <a href="tel:02134392918"
                           class="ayk-office-action-v2">

                            Contact Islamabad Office
                            <i class="fas fa-arrow-right"></i>

                        </a>

                    </div>
                </div>
            </div>


            <!-- Karachi Office Card -->
            <div class="col-12 col-md-6 col-xl-4">

                <div class="ayk-office-card-v2">

                    <div class="ayk-office-image-v2">

                        <img src="img/office-1.jpg"
                             alt="AYK Overseas Karachi Office"
                             loading="lazy">

                        <span class="ayk-office-city-v2">
                            Karachi
                        </span>

                    </div>

                    <div class="ayk-office-body-v2">

                        <div class="ayk-office-location-label-v2">
                            <i class="fas fa-location-dot"></i>
                            Karachi Office
                        </div>

                        <h3>Karachi</h3>

                        <!--<div class="ayk-office-contact-v2">-->

                        <!--    <a href="#"-->
                        <!--       class="ayk-employer-wa-trigger ayk-office-contact-item-v2"-->
                        <!--       role="button"-->
                        <!--       aria-haspopup="dialog"-->
                        <!--       aria-controls="aykEmployerWaModal">-->

                        <!--        <span class="ayk-office-icon-v2">-->
                        <!--            <i class="fab fa-whatsapp"></i>-->
                        <!--        </span>-->

                        <!--        <span>-->
                        <!--            <small style="color: #000000;">-->
                        <!--                Employer Line-->
                        <!--            </small>-->

                        <!--            +92 330 1922919-->

                        <!--            <span class="ayk-inline-notice-v2">-->
                        <!--                (For Companies & Employers Only)-->
                        <!--            </span>-->
                        <!--        </span>-->

                        <!--    </a>-->
                        
                        
                        
                        
                        
                        
                         <div class="ayk-office-contact-v2">

                            <a href="tel:02134392918"
                               class="ayk-office-contact-item-v2"
                               role="button"
                               aria-haspopup="dialog"
                               aria-controls="aykEmployerWaModal">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Employer Line
                                    </small>

                                   02134392918

                                    <span class="ayk-inline-notice-v2">
                                        (For Companies & Employers Only)
                                    </span>
                                </span>

                            </a>

                        
                        

                            <a href="tel:02134392918"
                               class="ayk-office-contact-item-v2">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Job Applicant Mobile Line
                                    </small>

                                    02134392918

                                    <span class="ayk-inline-notice-v2">
                                        (For Job Applications)
                                    </span>
                                </span>

                            </a>

                            <a href="tel:02134392918"
                               class="ayk-office-contact-item-v2">

                                <span class="ayk-office-icon-v2">
                                    <i class="fas fa-phone"></i>
                                </span>

                                <span>
                                    <small style="color: #000000;">
                                        Landline
                                    </small>

                                    021 34392918
                                </span>

                            </a>

                        </div>

                        <div class="ayk-office-address-v2">

                            <i class="fas fa-location-dot"></i>

                            <!--<p style="color: #000000;">-->
                            <!--    Office No 402, 4th Floor, Merium Heights,-->
                            <!--    Near Baloch Pull, Shahra-e-Faisal, Karachi.-->
                            <!--</p>-->
                            
                            <p style="color: #000000;">
                                Office No. 402, 4th Floor, Merium Heights, Baloch Colony, 
Near Maqbool Masjid, Kathiawar Society Block A, Bangalore Town, 
Shahra-e-Faisal, Karachi 75160, Pakistan
                            </p>

                        </div>

                        <a href="tel:02134392918"
                           class="ayk-office-action-v2"
                           target="_blank"
                           rel="noopener">

                            Contact Karachi Office
                            <i class="fas fa-arrow-right"></i>

                        </a>

                    </div>
                </div>
            </div>

        </div>
    </div>
</section>






<div class="ayk-contact-map-card">

    <div class="ayk-contact-map-heading">

        <div>

            <span class="ayk-contact-kicker">
                FIND US
            </span>

            <h3>
                Visit Our Office
            </h3>

            <p>
                Find our Karachi office and connect with
                the AYK Overseas team.
            </p>

        </div>

        <a
            href="https://www.google.com/maps/search/?api=1&query=THE+AYK+OVERSEAS+BUREAU+GL+4586-KAR"
            target="_blank"
            rel="noopener"
            class="ayk-contact-map-link"
        >
            Open in Google Maps
            <i class="fas fa-arrow-up-right-from-square"></i>
        </a>

    </div>

    <div class="ayk-contact-map">

        <iframe
            title="AYK Overseas Office Location - Google Maps"
            loading="lazy"
            src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3619.871706947339!2d67.08043677529689!3d24.868230944946642!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3eb33d3d4c471cf3%3A0x2cf569907a21d05!2sTHE%20AYK%20OVERSEAS%20BUREAU%20GL%204586-KAR!5e0!3m2!1sen!2s!4v1763708722657!5m2!1sen!2s"
            width="800"
            height="600"
            style="border:0;"
            allowfullscreen
            referrerpolicy="no-referrer-when-downgrade"
        ></iframe>

    </div>

</div>





<section class="faq-sec">

    <div class="faq-container">

     
       <h3 style="text-align: center; font-size: 32px; font-weight: 600;">Employer FAQs</h3>
        <p class="faq-sub" style="font-size: 16px !important; color: #000000 !important;">Everything you need to know about hiring manpower from Pakistan.</p>

        <div class="faq-item active">
            <button>How Can Employers Hire Manpower from Pakistan?</button>
            <div class="faq-content">
                You can share your manpower requirements with us via our website, email, or WhatsApp. Once received, we begin sourcing and provide shortlisted candidates for your review.
            </div>
        </div>

        <div class="faq-item">
            <button>Do You Provide Bulk Manpower Recruitment for Large Projects?</button>
            <div class="faq-content">
                Yes, we specialize in bulk hiring and can efficiently supply manpower for small to large-scale projects across various industries.
            </div>
        </div>

        <div class="faq-item">
            <button>Which Industries Does Your Manpower Recruitment Agency Serve?</button>
            <div class="faq-content">
                We provide manpower recruitment services from Pakistan for construction workers, oil and gas, medical staff, facility management, IT, manufacturing, logistics and engineering sectors.
            </div>
        </div>

        <div class="faq-item">
            <button>Are Pakistani Workers Pre-Screened, Verified &amp; Trade-Tested?</button>
            <div class="faq-content">
                Yes, candidates are screened according to the employer's requirements, with trade testing arranged where required.
            </div>
        </div>

        <div class="faq-item">
            <button>What Is Your Overseas Recruitment Process?</button>
            <div class="faq-content">
                Our process includes requirement analysis, candidate sourcing, screening, shortlisting, interviews, documentation, visa processing, and deployment.
            </div>
        </div>

        <div class="faq-item">
            <button>How Long Does It Take to Deploy Workers?</button>
            <div class="faq-content">
                Timelines depend on the destination country, job category, documentation and visa approvals. We share a project-specific timeline after receiving your requirement.
            </div>
        </div>

        <div class="faq-item">
            <button>Are You a Licensed Recruitment Agency?</button>
            <div class="faq-content">
                Yes, we are a government licensed overseas recruitment agency in Pakistan and fully compliant with international recruitment standards.
            </div>
        </div>

        <div class="faq-item">
            <button>Do You Handle Visa and Documentation?</button>
            <div class="faq-content">
                Yes, we provide complete support including visa processing, documentation, medical tests, attestation, and travel coordination.
            </div>
        </div>

        <div class="faq-item">
            <button>Can You Become Our Official Recruitment Vendor?</button>
            <div class="faq-content">
                Yes, we are open for vendor registration and long-term partnerships. We can follow your onboarding and compliance process.
            </div>
        </div>

        <div class="faq-item">
            <button>What if a Worker Does Not Perform Well?</button>
            <div class="faq-content">
                We offer a replacement guarantee as per agreement to ensure your satisfaction and smooth project execution.
            </div>
        </div>

        <div class="faq-item">
            <button>What Are the Costs Involved in Hiring?</button>
            <div class="faq-content">
                Costs depend on job category, volume, and employer requirements. We provide transparent pricing after understanding your needs.
            </div>
        </div>

        <div class="faq-item">
            <button>How Do We Get Started?</button>
            <div class="faq-content">
                Simply contact us or submit your manpower request. Our team will guide you and start the recruitment process immediately.
            </div>
        </div>

    </div>

</section>

</main>





































<style>
    .ayk-wd-overlay{
        position:fixed;
        inset:0;
        z-index:99999;
        background:rgba(10,20,35,.55);
        backdrop-filter:blur(3px);
        display:flex;
        align-items:center;
        justify-content:center;
        padding:18px;
        opacity:0;
        visibility:hidden;
        transition:opacity .25s ease, visibility .25s ease;
    }
    .ayk-wd-overlay.is-open{ opacity:1; visibility:visible; }

    .ayk-wd-modal{
        width:100%;
        max-width:460px;
        background:#ffffff;
        border-radius:20px;
        overflow:hidden;
        box-shadow:0 25px 60px rgba(0,0,0,.35);
        transform:translateY(24px) scale(.96);
        transition:transform .3s ease;
    }
    .ayk-wd-overlay.is-open .ayk-wd-modal{ transform:translateY(0) scale(1); }

    .ayk-wd-head{
        position:relative;
        padding:26px 24px 22px;
        background:linear-gradient(120deg,#0c2340 0%,#153a63 55%,#c8102e 160%);
        color:#fff;
        text-align:center;
    }
    .ayk-wd-head i.ayk-wd-wa-icon{
        display:inline-flex;
        align-items:center;
        justify-content:center;
        width:52px;
        height:52px;
        border-radius:50%;
        background:rgba(255,255,255,.12);
        border:1px solid rgba(255,255,255,.35);
        font-size:26px;
        color:#25D366;
        margin-bottom:12px;
    }
    .ayk-wd-head h3{
        margin:0 0 6px;
        font-size:19px;
        font-weight:700;
        letter-spacing:.2px;
        color:#ffffff !important;
    }
    .ayk-wd-head p{
        margin:0;
        font-size:12.5px;
        color:rgba(255,255,255,.85);
        line-height:1.6;
    }
    .ayk-wd-close{
        position:absolute;
        top:14px;
        right:14px;
        width:30px;
        height:30px;
        border-radius:50%;
        border:none;
        background:rgba(255,255,255,.15);
        color:#fff;
        font-size:14px;
        cursor:pointer;
        display:flex;
        align-items:center;
        justify-content:center;
        transition:background .2s ease;
    }
    .ayk-wd-close:hover{ background:rgba(255,255,255,.3); }

    .ayk-wd-body{
        padding:22px;
        display:flex;
        flex-direction:column;
        gap:14px;
        background:#f7f9fc;
    }

    .ayk-wd-option{
        display:flex;
        align-items:center;
        gap:14px;
        padding:16px;
        border-radius:14px;
        background:#ffffff;
        border:1px solid #e7edf5;
        text-decoration:none;
        transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease;
    }
    .ayk-wd-option:hover{
        transform:translateY(-3px);
        box-shadow:0 12px 24px rgba(9,62,120,.12);
        border-color:transparent;
    }

    .ayk-wd-option .ayk-wd-ico{
        flex:0 0 auto;
        width:48px;
        height:48px;
        border-radius:50%;
        display:flex;
        align-items:center;
        justify-content:center;
        font-size:20px;
        color:#fff;
    }
    .ayk-wd-job .ayk-wd-ico{ background:linear-gradient(135deg,#0b63ce,#142d4f); }
    .ayk-wd-corp .ayk-wd-ico{ background:linear-gradient(135deg,#c8102e,#8c0c20); }

    .ayk-wd-option .ayk-wd-txt{ flex:1 1 auto; }
    .ayk-wd-option .ayk-wd-txt strong{
        display:block;
        font-size:14.5px;
        color:#142d4f;
        margin-bottom:2px;
    }
    .ayk-wd-option .ayk-wd-txt span{
        display:block;
        font-size:11.5px;
        color:#7a8797;
        line-height:1.5;
    }
    .ayk-wd-option .ayk-wd-arrow{
        flex:0 0 auto;
        width:34px;
        height:34px;
        border-radius:50%;
        background:#eef4fb;
        color:#25D366;
        display:flex;
        align-items:center;
        justify-content:center;
        font-size:15px;
    }

    .ayk-wd-foot{
        padding:14px 22px 20px;
        text-align:center;
        background:#f7f9fc;
    }
    .ayk-wd-foot span{
        font-size:11px;
        color:#9aa5b3;
    }

    @media (max-width:480px){
        .ayk-wd-head{ padding:22px 18px 18px; }
        .ayk-wd-body{ padding:18px; }
    }
</style>

<div class="ayk-wd-overlay" id="aykWdOverlay">
    <div class="ayk-wd-modal">

        <div class="ayk-wd-head">
            <button type="button" class="ayk-wd-close" id="aykWdClose" aria-label="Close">
                <i class="fas fa-times"></i>
            </button>
            <i class="fab fa-whatsapp ayk-wd-wa-icon"></i>
            <h3>Chat With AYK On WhatsApp</h3>
            <p>Select an option below so we can connect you with the right team.</p>
        </div>

        <div class="ayk-wd-body">

            <!--<a href="https://wa.me/923231208216?text=Hello%20AYK%20Team%2C%20I%20want%20to%20apply%20for%20a%20job."-->
            <!--   target="_blank" rel="noopener" class="ayk-wd-option ayk-wd-job">-->
            <!--<a href="tel:02134392918" class="ayk-wd-option ayk-wd-job">-->
            <!--    <span class="ayk-wd-ico"><i class="fas fa-user-tie"></i></span>-->
            <!--    <span class="ayk-wd-txt">-->
            <!--        <strong>Apply For a Job</strong>-->
            <!--         <span>Call Our PTCL Helpline</span>-->
                    <!--<span>Overseas &amp; local job seekers</span>-->
            <!--    </span>-->
            <!--    <span class="ayk-wd-arrow"><i class="fas fa-phone"></i></span>-->
            <!--</a>-->
            
             <a href="https://wa.me/923354392910?text=Hello%20AYK%20Team%2C%20I%20want%20to%20apply%20for%20a%20job."
               target="_blank" rel="noopener" class="ayk-wd-option ayk-wd-job">
                <span class="ayk-wd-ico"><i class="fas fa-user-tie"></i></span>
                <span class="ayk-wd-txt">
                    <strong>Apply for a Job</strong>
                    <span>Overseas &amp; local job seekers</span>
                </span>
                <span class="ayk-wd-arrow"><i class="fab fa-whatsapp"></i></span>
            </a>

            <a href="https://wa.me/923301922919?text=Hello%20AYK%20Team%2C%20our%20company%20needs%20manpower."
               target="_blank" rel="noopener" class="ayk-wd-option ayk-wd-corp">
                <span class="ayk-wd-ico"><i class="fas fa-building"></i></span>
                <span class="ayk-wd-txt">
                    <strong>For Employers Seeking Manpower </strong>
                    <span>Companies &amp; project employers</span>
                </span>
                <span class="ayk-wd-arrow"><i class="fab fa-whatsapp"></i></span>
            </a>

        </div>

        <div class="ayk-wd-foot">
            <span>AYK Overseas Recruitment &amp; HR Manpower Agency</span>
        </div>

    </div>
</div>

<script>
(function () {
    var openBtn = document.getElementById('aykWdOpenBtn');
    var overlay = document.getElementById('aykWdOverlay');
    var closeBtn = document.getElementById('aykWdClose');

    // function openWd() {
    function openWd(e) {
        if (e) e.preventDefault();
        if (overlay) {
            overlay.classList.add('is-open');
            document.body.style.overflow = 'hidden';
        }
    }

    function closeWd() {
        if (overlay) {
            overlay.classList.remove('is-open');
            document.body.style.overflow = '';
        }
    }

    // Global Click Handler (Ye guaranteed modal open karega aur redirect roke ga)
    // document.addEventListener('click', function (e) {
    //     var openBtn = e.target.closest('#aykWdOpenBtn, #aykWdOpenBtnTop');
        
    //     if (openBtn) {
    //         e.preventDefault(); // Redirect hone se rokta hai
    //         openWd();
    //     }
    // });
 if (openBtn) openBtn.addEventListener('click', openWd);
    if (closeBtn) closeBtn.addEventListener('click', closeWd);

    if (overlay) {
        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) closeWd();
        });
    }

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeWd();
    });
})();
</script>




















































<script>
(function () {
    function activateWhenNearViewport(selector, callback) {
        var el = document.querySelector(selector);
        if (!el) return;

        if (!('IntersectionObserver' in window)) {
            callback(el);
            return;
        }

        var observer = new IntersectionObserver(function (entries, obs) {
            if (entries.some(function (entry) { return entry.isIntersecting; })) {
                obs.disconnect();
                callback(el);
            }
        }, { rootMargin: '600px 0px' });

        observer.observe(el);
    }

    activateWhenNearViewport('.clients-track', function (track) {
        if (!track.dataset.loopReady) {
            var original = Array.prototype.slice.call(track.children);
            original.forEach(function (item) {
                var clone = item.cloneNode(true);
                clone.querySelectorAll('img').forEach(function (img) {
                    img.setAttribute('aria-hidden', 'true');
                    img.setAttribute('tabindex', '-1');
                });
                track.appendChild(clone);
            });
            track.dataset.loopReady = '1';
        }
        track.style.removeProperty('animation-play-state');
    });

    activateWhenNearViewport('.testi-track', function (track) {
        track.style.removeProperty('animation-play-state');
    });
})();
</script>



<?php include("includes/footer.php"); ?>
<?php include __DIR__ . '/includes/ayk-assistant.php'; ?>

<script src="js/homepage-performance.js" defer></script>