import React from 'react';
import { Trans } from 'react-i18next';

import {
    checkFiltered,
    checkRewrite,
    checkWhiteList,
    checkBlackList,
    checkBlockedService,
} from '../../../helpers/helpers';
import { SERVICES, FILTERED, CUSTOM_FILTERING_RULES_ID } from '../../../helpers/constants';
import PopoverFiltered from '../../ui/PopoverFilter';

const getFilterName = (filters, whitelistFilters, filterId, t) => {
    if (filterId === CUSTOM_FILTERING_RULES_ID) {
        return t('custom_filter_rules');
    }

    const filter = filters.find(filter => filter.id === filterId)
        || whitelistFilters.find(filter => filter.id === filterId);
    let filterName = '';

    if (filter) {
        filterName = filter.name;
    }

    if (!filterName) {
        filterName = t('unknown_filter', { filterId });
    }

    return filterName;
};

const normalizeResponse = response => (
    response.map((response) => {
        const { value, type, ttl } = response;
        return `${type}: ${value} (ttl=${ttl})`;
    })
);

const renderResponseList = (response, status) => {
    if (response.length > 0) {
        const listItems = response.map((response, index) => (
            <li key={index} title={response} className="logs__list-item">
                {response}
            </li>
        ));

        return <ul className="list-unstyled">{listItems}</ul>;
    }

    return (
        <div>
            <Trans values={{ value: status }}>query_log_response_status</Trans>
        </div>
    );
};

const renderTooltip = (isFiltered, rule, filter, service) =>
    isFiltered && <PopoverFiltered rule={rule} filter={filter} service={service} />;

const getResponseCell = (filtering, t) =>
    function cell(row) {
        const { value: responses, original } = row;
        const {
            reason, filterId, rule, status, originalAnswer,
        } = original;
        const { filters, whitelistFilters } = filtering;

        const isFiltered = checkFiltered(reason);
        const isBlackList = checkBlackList(reason);
        const isRewrite = checkRewrite(reason);
        const isWhiteList = checkWhiteList(reason);
        const isBlockedService = checkBlockedService(reason);
        const isBlockedCnameIp = originalAnswer;

        const filterKey = reason.replace(FILTERED, '');
        const parsedFilteredReason = t('query_log_filtered', { filter: filterKey });
        const currentService = SERVICES.find(service => service.id === original.serviceName);
        const serviceName = currentService && currentService.name;
        const filterName = getFilterName(filters, whitelistFilters, filterId, t);

        if (isBlockedCnameIp) {
            const normalizedAnswer = normalizeResponse(originalAnswer);

            return (
                <div className="logs__row logs__row--column">
                    <div className="logs__text-wrap">
                        <span className="logs__text">
                            <Trans>blocked_by_response</Trans>
                        </span>
                        {this.renderTooltip(isFiltered, rule, filterName)}
                    </div>
                    <div className="logs__list-wrap">
                        {renderResponseList(normalizedAnswer, status)}
                    </div>
                </div>
            );
        }

        return (
            <div className="logs__row logs__row--column">
                <div className="logs__text-wrap">
                    {(isFiltered || isBlockedService) && !isBlackList && (
                        <span className="logs__text" title={parsedFilteredReason}>
                            {parsedFilteredReason}
                        </span>
                    )}
                    {isBlackList && (
                        <span className="logs__text">
                            <Trans values={{ filter: filterName }}>
                                query_log_filtered
                            </Trans>
                        </span>
                    )}
                    {isBlockedService
                        ? renderTooltip(isFiltered, '', '', serviceName)
                        : renderTooltip(isFiltered, rule, filterName)}
                    {isRewrite && (
                        <strong>
                            <Trans>rewrite_applied</Trans>
                        </strong>
                    )}
                </div>
                <div className="logs__list-wrap">
                    {renderResponseList(responses, status)}
                    {isWhiteList && renderTooltip(isWhiteList, rule, filterName)}
                </div>
            </div>
        );
    };

export default getResponseCell;
