import React from 'react';
import { Trans } from 'react-i18next';
import { HashLink as Link } from 'react-router-hash-link';

import Card from '../ui/Card';

const Disabled = () => (
    <Card>
        <div className="lead text-center py-6">
            <Trans
                components={[
                    <Link to="/settings#logs-config" key="0">
                        link
                    </Link>,
                ]}
            >
                query_log_disabled
            </Trans>
        </div>
    </Card>
);

export default Disabled;
